//! Extract transaction metadata from a caller-authenticated runtime Wasm.
//!
//! This program does not authenticate the Wasm or authorize signing. Its caller
//! must prove :code membership under an owned finalized state root, pin this
//! executable, and impose subprocess resource and wall-clock limits. No storage,
//! network, clock, signature or offchain host requests are serviced.

use sha2::{Digest, Sha256};
use smoldot::executor::{DEFAULT_HEAP_PAGES, host, vm};
use std::io::{self, Read};

const MAX_CODE: usize = 8 * 1024 * 1024;
const MAX_METADATA: usize = 16 * 1024 * 1024;

fn metadata_bytes(encoded: &[u8]) -> Result<&[u8], &'static str> {
    let first = *encoded.first().ok_or("metadata_empty")?;
    let (length, prefix) = match first & 3 {
        0 => ((first >> 2) as usize, 1),
        1 => {
            let bytes: [u8; 2] = encoded
                .get(..2)
                .ok_or("metadata_length")?
                .try_into()
                .map_err(|_| "metadata_length")?;
            let length = (u16::from_le_bytes(bytes) >> 2) as usize;
            if length < 64 {
                return Err("metadata_noncanonical_length");
            }
            (length, 2)
        }
        2 => {
            let bytes: [u8; 4] = encoded
                .get(..4)
                .ok_or("metadata_length")?
                .try_into()
                .map_err(|_| "metadata_length")?;
            let length = (u32::from_le_bytes(bytes) >> 2) as usize;
            if length < 16384 {
                return Err("metadata_noncanonical_length");
            }
            (length, 4)
        }
        // Canonical mode 3 lengths start at 1 GiB, beyond our output bound.
        _ => return Err("metadata_length_limit"),
    };
    if length > MAX_METADATA || encoded.len() != length + prefix {
        return Err("metadata_length_limit");
    }
    let metadata = &encoded[prefix..];
    if !metadata.starts_with(b"meta") || metadata.len() < 5 {
        return Err("metadata_magic");
    }
    Ok(metadata)
}

fn inspect(code: &[u8]) -> Result<serde_json::Value, &'static str> {
    if code.is_empty() || code.len() > MAX_CODE {
        return Err("code_size_limit");
    }
    let prototype = host::HostVmPrototype::new(host::Config {
        module: code,
        heap_pages: DEFAULT_HEAP_PAGES,
        exec_hint: vm::ExecHint::ValidateAndExecuteOnce,
        // Runtimes can import hosts unrelated to Metadata_metadata. Smoldot
        // traps if any unresolved import is actually called.
        allow_unresolved_imports: true,
    })
    .map_err(|_| "runtime_initialization_failed")?;
    let version = prototype.runtime_version().decode();
    let spec = version.spec_version;
    let transaction = version
        .transaction_version
        .ok_or("transaction_version_missing")?;
    let state = u8::from(version.state_version.ok_or("state_version_missing")?);
    let mut machine: host::HostVm = prototype
        .run_no_param(
            "Metadata_metadata",
            host::StorageProofSizeBehavior::proof_recording_disabled(),
        )
        .map_err(|_| "metadata_entrypoint_failed")?
        .into();
    loop {
        machine = match machine {
            host::HostVm::ReadyToRun(runner) => runner.run(),
            host::HostVm::GetMaxLogLevel(request) => request.resume(0),
            host::HostVm::LogEmit(request) => request.resume(),
            host::HostVm::Finished(finished) => {
                let value = finished.value();
                let metadata = metadata_bytes(value.as_ref())?;
                return Ok(serde_json::json!({
                    "schema": "umi-runtime-metadata-execution/1",
                    "runtime_code_sha256": hex::encode(Sha256::digest(code)),
                    "metadata_sha256": hex::encode(Sha256::digest(metadata)),
                    "metadata_hex": hex::encode(metadata),
                    "spec_version": spec,
                    "transaction_version": transaction,
                    "state_version": state,
                    "chain_submission_authorized": false,
                }));
            }
            host::HostVm::Error { .. } => return Err("metadata_execution_failed"),
            _ => return Err("metadata_external_request_forbidden"),
        };
    }
}

fn main() {
    // Bound pure Wasm execution independently of the parent's wall timer.
    // No runtime host request can access process resources or change limits.
    #[cfg(unix)]
    for (resource, ceiling) in [
        (libc::RLIMIT_CPU, 40),
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_NOFILE, 32),
        (libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024),
    ] {
        let limit = libc::rlimit {
            rlim_cur: ceiling,
            rlim_max: ceiling,
        };
        // SAFETY: limit points to a valid rlimit for this process only.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            eprintln!("resource_limit_failed");
            std::process::exit(1);
        }
    }
    #[cfg(not(unix))]
    {
        eprintln!("unsupported_execution_platform");
        std::process::exit(1);
    }
    let mut code = Vec::new();
    let result = io::stdin()
        .take((MAX_CODE + 1) as u64)
        .read_to_end(&mut code)
        .map_err(|_| "code_read_failed")
        .and_then(|_| inspect(&code));
    match result {
        Ok(result) => println!("{result}"),
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_canonical_vector_only() {
        assert_eq!(metadata_bytes(b"\x14meta\x0e").unwrap(), b"meta\x0e");
        for value in [
            b"".as_slice(),
            b"\x14meta",
            b"\x14meta\x0eX",
            b"\x14evil\x0e",
            b"\x15\x00meta\x0e",
            b"\x16\x00\x00\x00meta\x0e",
            b"\x03",
        ] {
            assert!(metadata_bytes(value).is_err());
        }
    }

    #[test]
    fn canonical_larger_vectors() {
        for length in [64usize, 16384, 65536] {
            let mut value = if length < 16384 {
                (((length as u16) << 2) | 1).to_le_bytes().to_vec()
            } else {
                (((length as u32) << 2) | 2).to_le_bytes().to_vec()
            };
            value.extend_from_slice(b"meta\x0e");
            value.resize(value.len() + length - 5, 0);
            assert_eq!(metadata_bytes(&value).unwrap().len(), length);
            value.push(0);
            assert!(metadata_bytes(&value).is_err());
        }
    }

    #[test]
    fn invalid_runtime_rejected() {
        assert!(inspect(b"").is_err());
        assert!(inspect(b"not Wasm").is_err());
        assert!(inspect(&vec![0; MAX_CODE + 1]).is_err());
    }
}
