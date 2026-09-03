use blake2::Blake2bVar;
use blake2::digest::{Update as BlakeUpdate, VariableOutput};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::num::NonZero;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use subxt_lightclient::{LightClient, LightClientRpc};
use thiserror::Error;

const REQUEST_SCHEMA: &str = "umi-grandpa-finality-observer/1";
const RECORD_SCHEMA: &str = "umi-grandpa-finality-attestation/1";
const EVIDENCE_CLASS: &str = "verifier_attested_finality";
const SOURCE_REVISION: &str = concat!(
    "subtensor-chain-spec:da06f033663896ef2fdbbfc3ecc68ca908fba0f5;",
    "subxt-lightclient:0.50.3@49ea25dcf81a6c764ed6d341679211a396191cc8+umi-database-input-v1;",
    "smoldot-light:1.3.2@5fe9121f81a58454542ac69a44c4d73f00f30283+umi-database-bootstrap-v1;",
    "smoldot:2.2.0@90e94869a7fbd617d28990da3005eaa906bc3862+umi-header-consensus-disambiguation-v1"
);
const TRANSCRIPT_DOMAIN: &[u8] = b"umi-grandpa-finality-attestation-v1\0";
const TIMESTAMP_NOW_KEY: &str =
    "0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb";
const MAXIMUM_CONFIG_BYTES: usize = 64 * 1024;
const AURA_SLOT_DURATION_MS: u64 = 12_000;
const BLOCK_NUMBER_BYTES: usize = 4;
const MAXIMUM_CHECKPOINT_AUTHORITIES: usize = 1_024;
const MAXIMUM_DIAGNOSTIC_LINES: usize = 32;
const MAXIMUM_DIAGNOSTIC_CHARACTERS: usize = 256;
const FINNEY_GENESIS_HASH: &str =
    "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03";
const FINNEY_CHAIN_SPEC_SHA256: &str =
    "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105";
const FINNEY_BOOTSTRAP_DATABASE_SHA256: &str =
    "44f1db866965c849184a1bb2b625f03958311a8a65a18a7b0a94587c97766763";
const CONFORMANCE_RESULT_SCHEMA: &str = "umi-grandpa-finality-conformance-result/1";
const CONFORMANCE_CASE_IDS: [&str; 6] = [
    "checkpoint-header-positive",
    "contiguous-first-positive",
    "contiguous-second-positive",
    "finney-checkpoint-positive",
    "missing-prefix-negative",
    "truncated-header-negative",
];

struct BoundedStderrLogger;

static STDERR_LOGGER: BoundedStderrLogger = BoundedStderrLogger;
static DIAGNOSTIC_LINES: AtomicUsize = AtomicUsize::new(0);

impl log::Log for BoundedStderrLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata())
            || DIAGNOSTIC_LINES.fetch_add(1, Ordering::Relaxed) >= MAXIMUM_DIAGNOSTIC_LINES
        {
            return;
        }
        let message: String = record
            .args()
            .to_string()
            .chars()
            .take(MAXIMUM_DIAGNOSTIC_CHARACTERS)
            .collect();
        eprintln!(
            "umi-grandpa-finality-observer [{}] {}: {}",
            record.level(),
            record.target(),
            message
        );
    }

    fn flush(&self) {}
}

fn initialize_diagnostics() {
    let level = if std::env::var_os("UMI_FINALITY_DEBUG").as_deref() == Some("1".as_ref()) {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    if log::set_logger(&STDERR_LOGGER).is_ok() {
        log::set_max_level(level);
    }
}

#[derive(Debug, Error)]
enum ObserverError {
    #[error("{0}")]
    InvalidConfig(&'static str),
    #[error("{0}")]
    InvalidChainSpec(&'static str),
    #[error("{0}")]
    Protocol(&'static str),
    #[error("chain specification I/O failed")]
    ChainSpecIo(#[source] io::Error),
    #[error("light client failed: {0}")]
    LightClient(String),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("startup timed out")]
    StartupTimeout,
    #[error("finality subscription ended")]
    SubscriptionEnded,
    #[error("output failed")]
    Output(#[source] io::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    request_id: String,
    chain_spec_path: PathBuf,
    chain_spec_sha256: String,
    expected_genesis_hash: String,
    bootstrap_block_number: u64,
    bootstrap_block_hash: String,
    minimum_finalized_block: u64,
    maximum_records: u32,
    startup_timeout_seconds: u64,
    maximum_chain_spec_bytes: u64,
    maximum_header_bytes: usize,
    maximum_ancestry_blocks: usize,
    maximum_record_bytes: usize,
}

struct ChainSpecMaterial {
    specification: String,
    database_content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrandpaWarpSyncCheckpoint {
    finalized_block_header: String,
    grandpa_authority_set: String,
}

#[derive(Debug, Serialize)]
struct ConformanceSelfTestReport {
    schema: &'static str,
    case_ids: [&'static str; 6],
    fixture_canonical_sha256: String,
    finney_checkpoint_canonical_sha256: String,
    ok: bool,
}

impl Config {
    fn validate(&self) -> Result<(), ObserverError> {
        if self.schema != REQUEST_SCHEMA {
            return Err(ObserverError::InvalidConfig("unsupported_schema"));
        }
        require_hex(&self.request_id, 32, false)
            .map_err(|_| ObserverError::InvalidConfig("invalid_request_id"))?;
        require_hex(&self.chain_spec_sha256, 32, false)
            .map_err(|_| ObserverError::InvalidConfig("invalid_chain_spec_sha256"))?;
        require_hex(&self.expected_genesis_hash, 32, true)
            .map_err(|_| ObserverError::InvalidConfig("invalid_genesis_hash"))?;
        require_hex(&self.bootstrap_block_hash, 32, true)
            .map_err(|_| ObserverError::InvalidConfig("invalid_bootstrap_hash"))?;
        if !self.chain_spec_path.is_absolute() {
            return Err(ObserverError::InvalidConfig("chain_spec_path_not_absolute"));
        }
        if self.maximum_records == 0 || self.maximum_records > 100_000 {
            return Err(ObserverError::InvalidConfig("invalid_maximum_records"));
        }
        if !(1..=86_400).contains(&self.startup_timeout_seconds) {
            return Err(ObserverError::InvalidConfig("invalid_startup_timeout"));
        }
        if !(1..=64 * 1024 * 1024).contains(&self.maximum_chain_spec_bytes) {
            return Err(ObserverError::InvalidConfig("invalid_chain_spec_limit"));
        }
        if !(128..=1024 * 1024).contains(&self.maximum_header_bytes) {
            return Err(ObserverError::InvalidConfig("invalid_header_limit"));
        }
        if !(1..=16_384).contains(&self.maximum_ancestry_blocks) {
            return Err(ObserverError::InvalidConfig("invalid_ancestry_limit"));
        }
        if !(1024..=16 * 1024 * 1024).contains(&self.maximum_record_bytes) {
            return Err(ObserverError::InvalidConfig("invalid_record_limit"));
        }
        if self.bootstrap_block_number == 0
            || self.bootstrap_block_hash == self.expected_genesis_hash
        {
            return Err(ObserverError::InvalidConfig("unsupported_bootstrap_source"));
        }
        if self.minimum_finalized_block <= self.bootstrap_block_number {
            return Err(ObserverError::InvalidConfig(
                "minimum_must_advance_checkpoint",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedHeader {
    number: u64,
    hash: String,
    parent_hash: String,
    state_root: String,
    extrinsics_root: String,
    scale_header: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AncestryEntry {
    number: u64,
    hash: String,
    parent_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct BlockRecord {
    number: u64,
    hash: String,
    parent_hash: String,
    state_root: String,
    extrinsics_root: String,
    scale_header: String,
    timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct UnsignedAttestation {
    schema: &'static str,
    request_id: String,
    evidence_class: &'static str,
    offline_finality_proof: bool,
    source_revision: &'static str,
    sequence: u64,
    chain_spec_sha256: String,
    genesis_hash: String,
    bootstrap_block_number: u64,
    bootstrap_block_hash: String,
    bootstrap_source: &'static str,
    bootstrap_selected: bool,
    startup_finalized_block_number: u64,
    startup_finalized_block_hash: String,
    block: BlockRecord,
    ancestry: Vec<AncestryEntry>,
    ancestry_complete_since_previous: bool,
    previous_finalized_hash: Option<String>,
    previous_transcript_digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct Attestation {
    schema: &'static str,
    request_id: String,
    evidence_class: &'static str,
    offline_finality_proof: bool,
    source_revision: &'static str,
    sequence: u64,
    chain_spec_sha256: String,
    genesis_hash: String,
    bootstrap_block_number: u64,
    bootstrap_block_hash: String,
    bootstrap_source: &'static str,
    bootstrap_selected: bool,
    startup_finalized_block_number: u64,
    startup_finalized_block_hash: String,
    block: BlockRecord,
    ancestry: Vec<AncestryEntry>,
    ancestry_complete_since_previous: bool,
    previous_finalized_hash: Option<String>,
    previous_transcript_digest: String,
    transcript_digest: String,
}

struct Transcript<'a> {
    config: &'a Config,
    previous_header: Option<DecodedHeader>,
    previous_timestamp_ms: Option<u64>,
    previous_digest: String,
    sequence: u64,
    startup_finalized_head: Option<(u64, String)>,
}

impl<'a> Transcript<'a> {
    fn new(config: &'a Config) -> Self {
        Self {
            config,
            previous_header: None,
            previous_timestamp_ms: None,
            previous_digest: "0".repeat(64),
            sequence: 0,
            startup_finalized_head: None,
        }
    }

    fn set_startup_finalized_head(&mut self, header: &DecodedHeader) -> Result<(), ObserverError> {
        if self.startup_finalized_head.is_some() {
            return Err(ObserverError::Protocol("duplicate_initialized_event"));
        }
        if header.number < self.config.bootstrap_block_number {
            return Err(ObserverError::Protocol("startup_head_before_checkpoint"));
        }
        if header.number == self.config.bootstrap_block_number
            && header.hash != self.config.bootstrap_block_hash
        {
            return Err(ObserverError::Protocol("startup_checkpoint_hash_mismatch"));
        }
        self.startup_finalized_head = Some((header.number, header.hash.clone()));
        Ok(())
    }

    fn record(
        &mut self,
        header: DecodedHeader,
        timestamp_ms: u64,
        ancestry: Vec<AncestryEntry>,
        ancestry_complete: bool,
    ) -> Result<Attestation, ObserverError> {
        let (startup_finalized_block_number, startup_finalized_block_hash) = self
            .startup_finalized_head
            .as_ref()
            .ok_or(ObserverError::Protocol("missing_initialized_event"))?;
        if header.number < self.config.minimum_finalized_block {
            return Err(ObserverError::Protocol("below_minimum_finalized_block"));
        }
        if ancestry.is_empty() || ancestry.len() > self.config.maximum_ancestry_blocks {
            return Err(ObserverError::Protocol("invalid_ancestry_length"));
        }
        let target = ancestry
            .last()
            .ok_or(ObserverError::Protocol("missing_ancestry_target"))?;
        if target.number != header.number
            || target.hash != header.hash
            || target.parent_hash != header.parent_hash
        {
            return Err(ObserverError::Protocol("ancestry_target_mismatch"));
        }

        let previous_hash = self.previous_header.as_ref().map(|item| item.hash.clone());
        match &self.previous_header {
            None => {
                if ancestry_complete || ancestry.len() != 1 {
                    return Err(ObserverError::Protocol("invalid_bootstrap_ancestry"));
                }
            }
            Some(previous) => {
                if !ancestry_complete {
                    return Err(ObserverError::Protocol(
                        "post_bootstrap_ancestry_incomplete",
                    ));
                }
                if header.number <= previous.number {
                    return Err(ObserverError::Protocol("finality_rollback"));
                }
                if ancestry[0].parent_hash != previous.hash
                    || ancestry[0].number != previous.number + 1
                    || ancestry.len() as u64 != header.number - previous.number
                {
                    return Err(ObserverError::Protocol("ancestry_gap"));
                }
                for pair in ancestry.windows(2) {
                    if pair[1].number != pair[0].number + 1 || pair[1].parent_hash != pair[0].hash {
                        return Err(ObserverError::Protocol("noncontiguous_ancestry"));
                    }
                }
                if timestamp_ms < self.previous_timestamp_ms.unwrap_or(0) {
                    return Err(ObserverError::Protocol("timestamp_rollback"));
                }
            }
        }

        let block = BlockRecord {
            number: header.number,
            hash: header.hash.clone(),
            parent_hash: header.parent_hash.clone(),
            state_root: header.state_root.clone(),
            extrinsics_root: header.extrinsics_root.clone(),
            scale_header: header.scale_header.clone(),
            timestamp_ms,
        };
        let unsigned = UnsignedAttestation {
            schema: RECORD_SCHEMA,
            request_id: self.config.request_id.clone(),
            evidence_class: EVIDENCE_CLASS,
            offline_finality_proof: false,
            source_revision: SOURCE_REVISION,
            sequence: self.sequence,
            chain_spec_sha256: self.config.chain_spec_sha256.clone(),
            genesis_hash: self.config.expected_genesis_hash.clone(),
            bootstrap_block_number: self.config.bootstrap_block_number,
            bootstrap_block_hash: self.config.bootstrap_block_hash.clone(),
            bootstrap_source: "grandpa_checkpoint",
            bootstrap_selected: true,
            startup_finalized_block_number: *startup_finalized_block_number,
            startup_finalized_block_hash: startup_finalized_block_hash.clone(),
            block,
            ancestry,
            ancestry_complete_since_previous: ancestry_complete,
            previous_finalized_hash: previous_hash,
            previous_transcript_digest: self.previous_digest.clone(),
        };
        let canonical = serde_jcs::to_vec(&unsigned)
            .map_err(|_| ObserverError::Protocol("canonicalization_failed"))?;
        let mut hasher = Sha256::new();
        ShaDigest::update(&mut hasher, TRANSCRIPT_DOMAIN);
        ShaDigest::update(&mut hasher, &canonical);
        let transcript_digest = hex::encode(hasher.finalize());
        let attestation = Attestation {
            schema: unsigned.schema,
            request_id: unsigned.request_id,
            evidence_class: unsigned.evidence_class,
            offline_finality_proof: unsigned.offline_finality_proof,
            source_revision: unsigned.source_revision,
            sequence: unsigned.sequence,
            chain_spec_sha256: unsigned.chain_spec_sha256,
            genesis_hash: unsigned.genesis_hash,
            bootstrap_block_number: unsigned.bootstrap_block_number,
            bootstrap_block_hash: unsigned.bootstrap_block_hash,
            bootstrap_source: unsigned.bootstrap_source,
            bootstrap_selected: unsigned.bootstrap_selected,
            startup_finalized_block_number: unsigned.startup_finalized_block_number,
            startup_finalized_block_hash: unsigned.startup_finalized_block_hash,
            block: unsigned.block,
            ancestry: unsigned.ancestry,
            ancestry_complete_since_previous: unsigned.ancestry_complete_since_previous,
            previous_finalized_hash: unsigned.previous_finalized_hash,
            previous_transcript_digest: unsigned.previous_transcript_digest,
            transcript_digest: transcript_digest.clone(),
        };
        let encoded = serde_jcs::to_vec(&attestation)
            .map_err(|_| ObserverError::Protocol("canonicalization_failed"))?;
        if encoded.len() > self.config.maximum_record_bytes {
            return Err(ObserverError::Protocol("record_size_limit"));
        }
        self.previous_header = Some(header);
        self.previous_timestamp_ms = Some(timestamp_ms);
        self.previous_digest = transcript_digest;
        self.sequence += 1;
        Ok(attestation)
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event")]
enum FollowEvent {
    #[serde(rename = "initialized")]
    Initialized {
        #[serde(rename = "finalizedBlockHashes")]
        finalized_block_hashes: Vec<String>,
    },
    #[serde(rename = "newBlock")]
    NewBlock {
        #[serde(rename = "blockHash")]
        block_hash: String,
        #[serde(rename = "parentBlockHash")]
        parent_block_hash: String,
        #[serde(rename = "newRuntime")]
        _new_runtime: Option<Value>,
    },
    #[serde(rename = "bestBlockChanged")]
    BestBlockChanged {
        #[serde(rename = "bestBlockHash")]
        _best_block_hash: String,
    },
    #[serde(rename = "finalized")]
    Finalized {
        #[serde(rename = "finalizedBlockHashes")]
        finalized_block_hashes: Vec<String>,
        #[serde(rename = "prunedBlockHashes")]
        pruned_block_hashes: Vec<String>,
    },
    #[serde(other)]
    Other,
}

fn require_hex(value: &str, bytes: usize, prefix: bool) -> Result<(), ()> {
    let digits = if prefix {
        value.strip_prefix("0x").ok_or(())?
    } else {
        if value.starts_with("0x") {
            return Err(());
        }
        value
    };
    if digits.len() != bytes * 2
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    Ok(())
}

fn decode_hash32(value: &str) -> Result<[u8; 32], ObserverError> {
    require_hex(value, 32, true).map_err(|_| ObserverError::InvalidConfig("invalid_hash"))?;
    hex::decode(&value[2..])
        .map_err(|_| ObserverError::InvalidConfig("invalid_hash"))?
        .try_into()
        .map_err(|_| ObserverError::InvalidConfig("invalid_hash"))
}

fn blake2_256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2 output is valid");
    BlakeUpdate::update(&mut hasher, bytes);
    hasher
        .finalize_variable(&mut output)
        .expect("output size was fixed at construction");
    output
}

fn decode_compact_u64(bytes: &[u8]) -> Result<(u64, usize), ObserverError> {
    let first = *bytes
        .first()
        .ok_or(ObserverError::Protocol("truncated_header"))?;
    match first & 0b11 {
        0 => Ok(((first >> 2) as u64, 1)),
        1 => {
            if bytes.len() < 2 {
                return Err(ObserverError::Protocol("truncated_header"));
            }
            let raw = u16::from_le_bytes([bytes[0], bytes[1]]) >> 2;
            if raw < (1 << 6) {
                return Err(ObserverError::Protocol("noncanonical_block_number"));
            }
            Ok((raw as u64, 2))
        }
        2 => {
            if bytes.len() < 4 {
                return Err(ObserverError::Protocol("truncated_header"));
            }
            let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) >> 2;
            if raw < (1 << 14) {
                return Err(ObserverError::Protocol("noncanonical_block_number"));
            }
            Ok((raw as u64, 4))
        }
        3 => {
            let length = ((first >> 2) as usize) + 4;
            if length > 8 || bytes.len() < length + 1 {
                return Err(ObserverError::Protocol("unsupported_block_number"));
            }
            let mut raw = 0u64;
            for (index, byte) in bytes[1..=length].iter().enumerate() {
                raw |= (*byte as u64) << (8 * index);
            }
            if raw < (1 << 30) || bytes[length] == 0 {
                return Err(ObserverError::Protocol("noncanonical_block_number"));
            }
            Ok((raw, length + 1))
        }
        _ => unreachable!(),
    }
}

fn decode_header(scale_hex: &str, maximum_bytes: usize) -> Result<DecodedHeader, ObserverError> {
    let digits = scale_hex
        .strip_prefix("0x")
        .ok_or(ObserverError::Protocol("header_missing_hex_prefix"))?;
    if digits.len() % 2 != 0 || digits.len() / 2 > maximum_bytes {
        return Err(ObserverError::Protocol("invalid_header_size"));
    }
    let bytes = hex::decode(digits).map_err(|_| ObserverError::Protocol("invalid_header_hex"))?;
    if bytes.len() < 32 + 1 + 32 + 32 + 1 {
        return Err(ObserverError::Protocol("truncated_header"));
    }
    let (number, compact_len) = decode_compact_u64(&bytes[32..])?;
    let roots_offset = 32 + compact_len;
    if bytes.len() < roots_offset + 64 + 1 {
        return Err(ObserverError::Protocol("truncated_header"));
    }
    let parent_hash = format!("0x{}", hex::encode(&bytes[..32]));
    let state_root = format!("0x{}", hex::encode(&bytes[roots_offset..roots_offset + 32]));
    let extrinsics_root = format!(
        "0x{}",
        hex::encode(&bytes[roots_offset + 32..roots_offset + 64])
    );
    Ok(DecodedHeader {
        number,
        hash: format!("0x{}", hex::encode(blake2_256(&bytes))),
        parent_hash,
        state_root,
        extrinsics_root,
        scale_header: format!("0x{}", digits),
    })
}

fn read_chain_spec(config: &Config) -> Result<ChainSpecMaterial, ObserverError> {
    let metadata =
        fs::symlink_metadata(&config.chain_spec_path).map_err(ObserverError::ChainSpecIo)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ObserverError::InvalidChainSpec("unsafe_chain_spec_path"));
    }
    if metadata.len() == 0 || metadata.len() > config.maximum_chain_spec_bytes {
        return Err(ObserverError::InvalidChainSpec("chain_spec_size_limit"));
    }
    let bytes = fs::read(&config.chain_spec_path).map_err(ObserverError::ChainSpecIo)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(ObserverError::InvalidChainSpec("chain_spec_changed"));
    }
    let mut hasher = Sha256::new();
    ShaDigest::update(&mut hasher, &bytes);
    if hex::encode(hasher.finalize()) != config.chain_spec_sha256 {
        return Err(ObserverError::InvalidChainSpec("chain_spec_hash_mismatch"));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| ObserverError::InvalidChainSpec("chain_spec_not_utf8"))?;
    prepare_chain_spec(config, &text)
}

fn decode_checkpoint_hex(value: &str) -> Result<Vec<u8>, ObserverError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(ObserverError::InvalidChainSpec(
            "checkpoint_missing_hex_prefix",
        ))?;
    if digits.is_empty()
        || digits.len() % 2 != 0
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ObserverError::InvalidChainSpec("invalid_checkpoint_hex"));
    }
    hex::decode(digits).map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_hex"))
}

fn decode_grandpa_authority_set(
    encoded: &str,
) -> Result<(u64, Vec<smoldot::header::GrandpaAuthority>), ObserverError> {
    let bytes = decode_checkpoint_hex(encoded)?;
    if bytes.len() < 9 {
        return Err(ObserverError::InvalidChainSpec(
            "invalid_checkpoint_authority_set",
        ));
    }
    let set_id = u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_authority_set"))?,
    );
    let (count, compact_len) = decode_compact_u64(&bytes[8..])
        .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_authority_set"))?;
    let count = usize::try_from(count)
        .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_authority_set"))?;
    if count == 0 || count > MAXIMUM_CHECKPOINT_AUTHORITIES {
        return Err(ObserverError::InvalidChainSpec(
            "invalid_checkpoint_authority_count",
        ));
    }
    let body = &bytes[8 + compact_len..];
    if body.len() != count.saturating_mul(40) {
        return Err(ObserverError::InvalidChainSpec(
            "invalid_checkpoint_authority_set",
        ));
    }
    let mut authorities = Vec::with_capacity(count);
    let mut unique = HashSet::with_capacity(count);
    let (authority_records, remainder) = body.as_chunks::<40>();
    debug_assert!(remainder.is_empty());
    for authority in authority_records {
        let public_key: [u8; 32] = authority[..32]
            .try_into()
            .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_authority_set"))?;
        let weight =
            u64::from_le_bytes(authority[32..].try_into().map_err(|_| {
                ObserverError::InvalidChainSpec("invalid_checkpoint_authority_set")
            })?);
        let weight = NonZero::new(weight).ok_or(ObserverError::InvalidChainSpec(
            "zero_checkpoint_authority_weight",
        ))?;
        if !unique.insert(public_key) {
            return Err(ObserverError::InvalidChainSpec(
                "duplicate_checkpoint_authority",
            ));
        }
        authorities.push(smoldot::header::GrandpaAuthority { public_key, weight });
    }
    Ok((set_id, authorities))
}

fn checkpoint_chain_information(
    config: &Config,
    checkpoint: &GrandpaWarpSyncCheckpoint,
) -> Result<smoldot::chain::chain_information::ValidChainInformation, ObserverError> {
    let header_bytes = decode_checkpoint_hex(&checkpoint.finalized_block_header)?;
    if header_bytes.len() > config.maximum_header_bytes {
        return Err(ObserverError::InvalidChainSpec(
            "checkpoint_header_size_limit",
        ));
    }
    let simple_header = decode_header(
        &checkpoint.finalized_block_header,
        config.maximum_header_bytes,
    )
    .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_header"))?;
    if simple_header.number != config.bootstrap_block_number
        || simple_header.hash != config.bootstrap_block_hash
    {
        return Err(ObserverError::InvalidChainSpec("checkpoint_drift"));
    }
    let decoded = smoldot::header::decode(&header_bytes, BLOCK_NUMBER_BYTES)
        .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_header"))?;
    if decoded.number != simple_header.number
        || format!("0x{}", hex::encode(decoded.hash(BLOCK_NUMBER_BYTES))) != simple_header.hash
    {
        return Err(ObserverError::InvalidChainSpec("checkpoint_drift"));
    }

    let (signing_set_id, signing_authorities) =
        decode_grandpa_authority_set(&checkpoint.grandpa_authority_set)?;
    if signing_authorities.is_empty() {
        return Err(ObserverError::InvalidChainSpec(
            "invalid_checkpoint_authority_count",
        ));
    }

    let mut aura_authorities = None;
    let mut next_grandpa_authorities = None;
    for log in decoded.digest.logs() {
        match log {
            smoldot::header::DigestItemRef::AuraConsensus(
                smoldot::header::AuraConsensusLogRef::AuthoritiesChange(authorities),
            ) => {
                if aura_authorities.is_some() {
                    return Err(ObserverError::InvalidChainSpec(
                        "duplicate_checkpoint_aura_change",
                    ));
                }
                let authorities: Vec<_> = authorities.map(Into::into).collect();
                if authorities.is_empty()
                    || authorities.len() > MAXIMUM_CHECKPOINT_AUTHORITIES
                    || authorities
                        .iter()
                        .map(|authority: &smoldot::header::AuraAuthority| authority.public_key)
                        .collect::<HashSet<_>>()
                        .len()
                        != authorities.len()
                {
                    return Err(ObserverError::InvalidChainSpec(
                        "invalid_checkpoint_aura_change",
                    ));
                }
                aura_authorities = Some(authorities);
            }
            smoldot::header::DigestItemRef::AuraConsensus(_) => {
                return Err(ObserverError::InvalidChainSpec(
                    "unexpected_checkpoint_aura_log",
                ));
            }
            smoldot::header::DigestItemRef::GrandpaConsensus(
                smoldot::header::GrandpaConsensusLogRef::ScheduledChange(change),
            ) => {
                if next_grandpa_authorities.is_some() || change.delay != 0 {
                    return Err(ObserverError::InvalidChainSpec(
                        "invalid_checkpoint_grandpa_change",
                    ));
                }
                let authorities: Vec<_> = change.next_authorities.map(Into::into).collect();
                if authorities.is_empty()
                    || authorities.len() > MAXIMUM_CHECKPOINT_AUTHORITIES
                    || authorities
                        .iter()
                        .map(|authority: &smoldot::header::GrandpaAuthority| authority.public_key)
                        .collect::<HashSet<_>>()
                        .len()
                        != authorities.len()
                {
                    return Err(ObserverError::InvalidChainSpec(
                        "invalid_checkpoint_grandpa_change",
                    ));
                }
                next_grandpa_authorities = Some(authorities);
            }
            smoldot::header::DigestItemRef::GrandpaConsensus(_) => {
                return Err(ObserverError::InvalidChainSpec(
                    "unexpected_checkpoint_grandpa_log",
                ));
            }
            _ => {}
        }
    }
    let after_finalized_block_authorities_set_id =
        signing_set_id
            .checked_add(1)
            .ok_or(ObserverError::InvalidChainSpec(
                "checkpoint_set_id_overflow",
            ))?;
    let information = smoldot::chain::chain_information::ChainInformation {
        finalized_block_header: Box::new(decoded.into()),
        consensus: smoldot::chain::chain_information::ChainInformationConsensus::Aura {
            finalized_authorities_list: aura_authorities.ok_or(ObserverError::InvalidChainSpec(
                "missing_checkpoint_aura_change",
            ))?,
            slot_duration: NonZero::new(AURA_SLOT_DURATION_MS).expect("slot duration is non-zero"),
        },
        finality: smoldot::chain::chain_information::ChainInformationFinality::Grandpa {
            after_finalized_block_authorities_set_id,
            finalized_triggered_authorities: next_grandpa_authorities.ok_or(
                ObserverError::InvalidChainSpec("missing_checkpoint_grandpa_change"),
            )?,
            finalized_scheduled_change: None,
        },
    };
    information
        .try_into()
        .map_err(|_| ObserverError::InvalidChainSpec("invalid_checkpoint_chain_information"))
}

fn prepare_chain_spec(
    config: &Config,
    chain_spec: &str,
) -> Result<ChainSpecMaterial, ObserverError> {
    let mut value: Value = serde_json::from_str(chain_spec)
        .map_err(|_| ObserverError::InvalidChainSpec("chain_spec_not_json"))?;
    let legacy_checkpoint = value
        .get("lightSyncState")
        .is_some_and(|item| !item.is_null());
    let grandpa_checkpoint = value
        .get("grandpaWarpSyncCheckpoint")
        .filter(|item| !item.is_null());
    if legacy_checkpoint && grandpa_checkpoint.is_some() {
        return Err(ObserverError::InvalidChainSpec(
            "ambiguous_checkpoint_profiles",
        ));
    }
    if legacy_checkpoint {
        return Err(ObserverError::InvalidChainSpec(
            "unsupported_legacy_bootstrap",
        ));
    }
    if let Some(raw_checkpoint) = grandpa_checkpoint {
        if config.expected_genesis_hash != FINNEY_GENESIS_HASH
            || config.chain_spec_sha256 != FINNEY_CHAIN_SPEC_SHA256
        {
            return Err(ObserverError::InvalidChainSpec(
                "unrecognized_grandpa_checkpoint_spec",
            ));
        }
        let checkpoint: GrandpaWarpSyncCheckpoint = serde_json::from_value(raw_checkpoint.clone())
            .map_err(|_| ObserverError::InvalidChainSpec("invalid_grandpa_checkpoint_schema"))?;
        let information = checkpoint_chain_information(config, &checkpoint)?;
        let chain =
            smoldot::database::finalized_serialize::encode_chain(&information, BLOCK_NUMBER_BYTES);
        let chain: Value = serde_json::from_str(&chain)
            .map_err(|_| ObserverError::InvalidChainSpec("bootstrap_encoding_failed"))?;
        let database_content = serde_json::to_string(&serde_json::json!({
            "genesisHash": config.expected_genesis_hash.trim_start_matches("0x"),
            "chain": chain,
            "nodes": {},
        }))?;
        if hex::encode(Sha256::digest(database_content.as_bytes()))
            != FINNEY_BOOTSTRAP_DATABASE_SHA256
        {
            return Err(ObserverError::InvalidChainSpec(
                "bootstrap_database_hash_mismatch",
            ));
        }
        value
            .as_object_mut()
            .ok_or(ObserverError::InvalidChainSpec("chain_spec_not_object"))?
            .remove("grandpaWarpSyncCheckpoint");
        let specification = serde_json::to_string(&value)?;
        return Ok(ChainSpecMaterial {
            specification,
            database_content,
        });
    }

    Err(ObserverError::InvalidChainSpec(
        "missing_pinned_grandpa_checkpoint",
    ))
}

fn raw_params(value: Value) -> Result<Box<RawValue>, ObserverError> {
    RawValue::from_string(serde_json::to_string(&value)?)
        .map_err(|_| ObserverError::Protocol("invalid_rpc_parameters"))
}

async fn rpc_value(
    rpc: &LightClientRpc,
    method: &str,
    params: Value,
) -> Result<Value, ObserverError> {
    let raw = rpc
        .request(method.to_owned(), Some(raw_params(params)?))
        .await
        .map_err(|error| ObserverError::LightClient(error.to_string()))?;
    serde_json::from_str(raw.get()).map_err(ObserverError::Json)
}

async fn header_at(
    rpc: &LightClientRpc,
    subscription_id: &str,
    hash: &str,
    maximum_bytes: usize,
) -> Result<DecodedHeader, ObserverError> {
    require_hex(hash, 32, true).map_err(|_| ObserverError::Protocol("invalid_block_hash"))?;
    let value = rpc_value(
        rpc,
        "chainHead_v1_header",
        serde_json::json!([subscription_id, hash]),
    )
    .await?;
    let encoded = value
        .as_str()
        .ok_or(ObserverError::Protocol("missing_pinned_header"))?;
    let header = decode_header(encoded, maximum_bytes)?;
    if header.hash != hash {
        return Err(ObserverError::Protocol("header_hash_mismatch"));
    }
    Ok(header)
}

async fn timestamp_at(rpc: &LightClientRpc, hash: &str) -> Result<u64, ObserverError> {
    let value = rpc_value(
        rpc,
        "state_getStorage",
        serde_json::json!([TIMESTAMP_NOW_KEY, hash]),
    )
    .await?;
    let encoded = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or(ObserverError::Protocol("missing_timestamp"))?;
    let bytes = hex::decode(encoded).map_err(|_| ObserverError::Protocol("invalid_timestamp"))?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ObserverError::Protocol("invalid_timestamp"))?;
    Ok(u64::from_le_bytes(bytes))
}

async fn unpin(
    rpc: &LightClientRpc,
    subscription_id: &str,
    hashes: &[String],
) -> Result<(), ObserverError> {
    if hashes.is_empty() {
        return Ok(());
    }
    rpc_value(
        rpc,
        "chainHead_v1_unpin",
        serde_json::json!([subscription_id, hashes]),
    )
    .await?;
    Ok(())
}

fn build_ancestry(
    target: &DecodedHeader,
    previous: &DecodedHeader,
    parents: &HashMap<String, String>,
    maximum_blocks: usize,
) -> Result<Vec<AncestryEntry>, ObserverError> {
    if target.number <= previous.number {
        return Err(ObserverError::Protocol("finality_rollback"));
    }
    let count = target.number - previous.number;
    if count as usize > maximum_blocks {
        return Err(ObserverError::Protocol("ancestry_size_limit"));
    }
    let mut reverse = Vec::with_capacity(count as usize);
    let mut current_hash = target.hash.clone();
    let mut current_parent = target.parent_hash.clone();
    let mut current_number = target.number;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current_hash.clone()) {
            return Err(ObserverError::Protocol("ancestry_cycle"));
        }
        reverse.push(AncestryEntry {
            number: current_number,
            hash: current_hash.clone(),
            parent_hash: current_parent.clone(),
        });
        if current_parent == previous.hash {
            break;
        }
        if current_number == 0 || reverse.len() >= maximum_blocks {
            return Err(ObserverError::Protocol("ancestry_gap"));
        }
        current_hash = current_parent;
        current_parent = parents
            .get(&current_hash)
            .cloned()
            .ok_or(ObserverError::Protocol("ancestry_gap"))?;
        current_number -= 1;
    }
    reverse.reverse();
    if reverse.len() as u64 != count {
        return Err(ObserverError::Protocol("ancestry_number_mismatch"));
    }
    Ok(reverse)
}

fn emit(record: &Attestation, maximum_bytes: usize) -> Result<(), ObserverError> {
    let encoded = serde_jcs::to_vec(record)
        .map_err(|_| ObserverError::Protocol("canonicalization_failed"))?;
    if encoded.len() > maximum_bytes {
        return Err(ObserverError::Protocol("record_size_limit"));
    }
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&encoded).map_err(ObserverError::Output)?;
    lock.write_all(b"\n").map_err(ObserverError::Output)?;
    lock.flush().map_err(ObserverError::Output)
}

async fn observe(config: &Config, chain_spec: ChainSpecMaterial) -> Result<(), ObserverError> {
    if chain_spec.database_content.is_empty() {
        return Err(ObserverError::InvalidChainSpec(
            "unsupported_bootstrap_source",
        ));
    }
    let expected_bootstrap_hash = decode_hash32(&config.bootstrap_block_hash)?;
    let (_client, rpc, bootstrap) = LightClient::relay_chain_with_database(
        chain_spec.specification,
        &chain_spec.database_content,
        config.bootstrap_block_number,
        expected_bootstrap_hash,
    )
    .map_err(|error| ObserverError::LightClient(error.to_string()))?;
    if bootstrap.block_number != config.bootstrap_block_number
        || bootstrap.block_hash != expected_bootstrap_hash
    {
        return Err(ObserverError::Protocol("bootstrap_receipt_mismatch"));
    }
    log::info!(
        target: "umi-bootstrap",
        "selected grandpa checkpoint #{} 0x{} from the verified database",
        bootstrap.block_number,
        hex::encode(bootstrap.block_hash)
    );
    let genesis = rpc_value(&rpc, "chainSpec_v1_genesisHash", serde_json::json!([])).await?;
    if genesis.as_str() != Some(config.expected_genesis_hash.as_str()) {
        return Err(ObserverError::Protocol("genesis_hash_mismatch"));
    }

    let mut subscription = rpc
        .subscribe(
            "chainHead_v1_follow".to_owned(),
            Some(raw_params(serde_json::json!([false]))?),
            "chainHead_v1_unfollow".to_owned(),
        )
        .await
        .map_err(|error| ObserverError::LightClient(error.to_string()))?;
    let subscription_id = subscription.id().to_owned();
    let mut parents: HashMap<String, String> = HashMap::new();
    let mut transcript = Transcript::new(config);
    let mut emitted = 0u32;
    let mut prebaseline_finalized: Option<String> = None;
    let startup_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(config.startup_timeout_seconds);

    loop {
        let notification = if emitted == 0 {
            tokio::time::timeout_at(startup_deadline, subscription.next())
                .await
                .map_err(|_| ObserverError::StartupTimeout)?
        } else {
            subscription.next().await
        };
        let raw = notification
            .ok_or(ObserverError::SubscriptionEnded)?
            .map_err(|error| ObserverError::LightClient(error.to_string()))?;
        let event: FollowEvent = serde_json::from_str(raw.get())?;
        let (targets, initialized) = match event {
            FollowEvent::Initialized {
                finalized_block_hashes,
            } => {
                if finalized_block_hashes.len() != 1 {
                    return Err(ObserverError::Protocol("invalid_initialized_event"));
                }
                (finalized_block_hashes, true)
            }
            FollowEvent::NewBlock {
                block_hash,
                parent_block_hash,
                ..
            } => {
                require_hex(&block_hash, 32, true)
                    .map_err(|_| ObserverError::Protocol("invalid_block_hash"))?;
                require_hex(&parent_block_hash, 32, true)
                    .map_err(|_| ObserverError::Protocol("invalid_parent_hash"))?;
                if let Some(existing) = parents.insert(block_hash, parent_block_hash.clone())
                    && existing != parent_block_hash
                {
                    return Err(ObserverError::Protocol("equivocating_header_event"));
                }
                continue;
            }
            FollowEvent::Finalized {
                finalized_block_hashes,
                pruned_block_hashes,
            } => {
                unpin(&rpc, &subscription_id, &pruned_block_hashes).await?;
                for pruned in &pruned_block_hashes {
                    parents.remove(pruned);
                }
                if finalized_block_hashes.is_empty() {
                    return Err(ObserverError::Protocol("empty_finalized_event"));
                }
                (finalized_block_hashes, false)
            }
            FollowEvent::BestBlockChanged { .. } | FollowEvent::Other => continue,
        };

        for target_hash in targets {
            let header = header_at(
                &rpc,
                &subscription_id,
                &target_hash,
                config.maximum_header_bytes,
            )
            .await?;
            if initialized {
                transcript.set_startup_finalized_head(&header)?;
                log::info!(
                    target: "umi-bootstrap",
                    "first verified finalized head #{} {}",
                    header.number,
                    header.hash
                );
            }
            if header.number < config.minimum_finalized_block {
                if let Some(previous) = prebaseline_finalized.replace(header.hash) {
                    unpin(&rpc, &subscription_id, &[previous]).await?;
                }
                continue;
            }
            let previous = transcript.previous_header.clone();
            let (ancestry, complete) = match previous.as_ref() {
                None => (
                    vec![AncestryEntry {
                        number: header.number,
                        hash: header.hash.clone(),
                        parent_hash: header.parent_hash.clone(),
                    }],
                    false,
                ),
                Some(previous) => (
                    build_ancestry(&header, previous, &parents, config.maximum_ancestry_blocks)?,
                    true,
                ),
            };
            let timestamp = timestamp_at(&rpc, &header.hash).await?;
            let record = transcript.record(header, timestamp, ancestry, complete)?;
            emit(&record, config.maximum_record_bytes)?;
            let mut obsolete = Vec::new();
            if let Some(prebaseline) = prebaseline_finalized.take() {
                obsolete.push(prebaseline);
            }
            if let Some(previous) = previous {
                obsolete.push(previous.hash);
                obsolete.extend(
                    record.ancestry[..record.ancestry.len() - 1]
                        .iter()
                        .map(|entry| entry.hash.clone()),
                );
            }
            obsolete.sort();
            obsolete.dedup();
            unpin(&rpc, &subscription_id, &obsolete).await?;
            for hash in obsolete {
                parents.remove(&hash);
            }
            emitted += 1;
            if emitted >= config.maximum_records {
                return Ok(());
            }
        }
    }
}

fn read_config() -> Result<Config, ObserverError> {
    let mut input = Vec::new();
    io::stdin()
        .take((MAXIMUM_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ObserverError::InvalidConfig("config_read_failed"))?;
    if input.is_empty() || input.len() > MAXIMUM_CONFIG_BYTES {
        return Err(ObserverError::InvalidConfig("config_size_limit"));
    }
    let config: Config = serde_json::from_slice(&input)?;
    config.validate()?;
    Ok(config)
}

// This helper is deliberately shared with the production SCALE-header decoder.
fn conformance_header(value: &Value) -> Result<DecodedHeader, ObserverError> {
    let object = value
        .as_object()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    if object.keys().map(String::as_str).collect::<HashSet<_>>()
        != HashSet::from(["hash", "number", "scale_header"])
    {
        return Err(ObserverError::Protocol("conformance_fixture_invalid"));
    }
    let scale_header = object
        .get("scale_header")
        .and_then(Value::as_str)
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    let expected_number = object
        .get("number")
        .and_then(Value::as_u64)
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    let expected_hash = object
        .get("hash")
        .and_then(Value::as_str)
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    let decoded = decode_header(scale_header, 4096)?;
    if decoded.number != expected_number || decoded.hash != expected_hash {
        return Err(ObserverError::Protocol("conformance_fixture_mismatch"));
    }
    Ok(decoded)
}

fn conformance_transcript_config() -> Config {
    Config {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "11".repeat(32),
        chain_spec_path: PathBuf::from("/umi-conformance/chain-spec.json"),
        chain_spec_sha256: "22".repeat(32),
        expected_genesis_hash: format!("0x{}", "33".repeat(32)),
        bootstrap_block_number: 1,
        bootstrap_block_hash: format!("0x{}", "44".repeat(32)),
        minimum_finalized_block: 2,
        maximum_records: 10,
        startup_timeout_seconds: 30,
        maximum_chain_spec_bytes: 1024,
        maximum_header_bytes: 4096,
        maximum_ancestry_blocks: 128,
        maximum_record_bytes: 64 * 1024,
    }
}

fn conformance_self_test() -> Result<Vec<u8>, ObserverError> {
    let fixture: Value = serde_json::from_slice(include_bytes!("../fixtures/finality-v1.json"))?;
    let object = fixture
        .as_object()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    if object.keys().map(String::as_str).collect::<HashSet<_>>()
        != HashSet::from([
            "checkpoint",
            "finney_checkpoint_fixture",
            "malformed_headers",
            "schema",
            "valid_contiguous",
        ])
        || object.get("schema").and_then(Value::as_str) != Some("umi-grandpa-finality-fixtures/1")
    {
        return Err(ObserverError::Protocol("conformance_fixture_invalid"));
    }

    conformance_header(&object["checkpoint"])?;
    let contiguous = object["valid_contiguous"]
        .as_object()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    if contiguous
        .keys()
        .map(String::as_str)
        .collect::<HashSet<_>>()
        != HashSet::from([
            "first",
            "first_timestamp_ms",
            "second",
            "second_timestamp_ms",
        ])
    {
        return Err(ObserverError::Protocol("conformance_fixture_invalid"));
    }
    let first = conformance_header(&contiguous["first"])?;
    let second = conformance_header(&contiguous["second"])?;
    let first_timestamp_ms = contiguous["first_timestamp_ms"]
        .as_u64()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    let second_timestamp_ms = contiguous["second_timestamp_ms"]
        .as_u64()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    let config = conformance_transcript_config();
    config.validate()?;
    let mut transcript = Transcript::new(&config);
    transcript.set_startup_finalized_head(&first)?;
    let first_record = transcript.record(
        first.clone(),
        first_timestamp_ms,
        vec![AncestryEntry {
            number: first.number,
            hash: first.hash.clone(),
            parent_hash: first.parent_hash.clone(),
        }],
        false,
    )?;
    let second_ancestry = build_ancestry(
        &second,
        &first,
        &HashMap::new(),
        config.maximum_ancestry_blocks,
    )?;
    let second_record = transcript.record(second, second_timestamp_ms, second_ancestry, true)?;
    if first_record.sequence != 0
        || second_record.sequence != 1
        || second_record.previous_transcript_digest != first_record.transcript_digest
        || second_record.previous_finalized_hash.as_deref() != Some(first.hash.as_str())
        || !second_record.ancestry_complete_since_previous
    {
        return Err(ObserverError::Protocol("conformance_continuity_mismatch"));
    }

    let malformed = object["malformed_headers"]
        .as_array()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    if malformed.len() != 2
        || malformed[0].as_str().is_none_or(|value| {
            !matches!(
                decode_header(value, 4096),
                Err(ObserverError::Protocol("truncated_header"))
            )
        })
        || malformed[1].as_str().is_none_or(|value| {
            !matches!(
                decode_header(value, 4096),
                Err(ObserverError::Protocol("header_missing_hex_prefix"))
            )
        })
    {
        return Err(ObserverError::Protocol("conformance_negative_case_failed"));
    }

    let finney: Value = serde_json::from_slice(include_bytes!(
        "../fixtures/finney-grandpa-checkpoint-v1.json"
    ))?;
    let finney_object = finney
        .as_object()
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    if finney_object
        .keys()
        .map(String::as_str)
        .collect::<HashSet<_>>()
        != HashSet::from([
            "block_hash",
            "block_number",
            "checkpoint",
            "schema",
            "source_revision",
        ])
        || finney_object.get("schema").and_then(Value::as_str)
            != Some("umi-finney-grandpa-checkpoint/1")
    {
        return Err(ObserverError::Protocol("conformance_fixture_invalid"));
    }
    let checkpoint = finney_object
        .get("checkpoint")
        .and_then(Value::as_object)
        .and_then(|value| value.get("finalizedBlockHeader"))
        .and_then(Value::as_str)
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    let decoded_checkpoint = decode_header(checkpoint, 4096)?;
    if Some(decoded_checkpoint.number) != finney_object.get("block_number").and_then(Value::as_u64)
        || Some(decoded_checkpoint.hash.as_str())
            != finney_object.get("block_hash").and_then(Value::as_str)
    {
        return Err(ObserverError::Protocol("conformance_fixture_mismatch"));
    }
    let mut finney_config = conformance_transcript_config();
    finney_config.expected_genesis_hash = FINNEY_GENESIS_HASH.to_owned();
    finney_config.chain_spec_sha256 = FINNEY_CHAIN_SPEC_SHA256.to_owned();
    finney_config.bootstrap_block_number = decoded_checkpoint.number;
    finney_config.bootstrap_block_hash = decoded_checkpoint.hash;
    finney_config.minimum_finalized_block = finney_config
        .bootstrap_block_number
        .checked_add(1)
        .ok_or(ObserverError::Protocol("conformance_fixture_invalid"))?;
    finney_config.validate()?;
    let checkpoint: GrandpaWarpSyncCheckpoint =
        serde_json::from_value(finney_object["checkpoint"].clone())?;
    checkpoint_chain_information(&finney_config, &checkpoint)?;

    let fixture_canonical = serde_jcs::to_vec(&fixture)
        .map_err(|_| ObserverError::Protocol("canonicalization_failed"))?;
    let finney_canonical = serde_jcs::to_vec(&finney)
        .map_err(|_| ObserverError::Protocol("canonicalization_failed"))?;
    serde_jcs::to_vec(&ConformanceSelfTestReport {
        schema: CONFORMANCE_RESULT_SCHEMA,
        case_ids: CONFORMANCE_CASE_IDS,
        fixture_canonical_sha256: hex::encode(Sha256::digest(&fixture_canonical)),
        finney_checkpoint_canonical_sha256: hex::encode(Sha256::digest(&finney_canonical)),
        ok: true,
    })
    .map_err(|_| ObserverError::Protocol("canonicalization_failed"))
}

#[tokio::main]
async fn main() {
    initialize_diagnostics();
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() == 2 && arguments[1] == "--conformance-self-test" {
        match conformance_self_test().and_then(|mut output| {
            output.push(b'\n');
            io::stdout()
                .write_all(&output)
                .map_err(ObserverError::Output)
        }) {
            Ok(()) => return,
            Err(error) => {
                eprintln!("umi-grandpa-finality-observer: {error}");
                std::process::exit(1);
            }
        }
    }
    if arguments.len() != 1 {
        eprintln!("umi-grandpa-finality-observer: unsupported command-line arguments");
        std::process::exit(1);
    }
    let result = async {
        let config = read_config()?;
        let chain_spec = read_chain_spec(&config)?;
        observe(&config, chain_spec).await?;
        Ok::<(), ObserverError>(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("umi-grandpa-finality-observer: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn finney_fixture() -> Value {
        serde_json::from_str(include_str!(
            "../fixtures/finney-grandpa-checkpoint-v1.json"
        ))
        .unwrap()
    }

    fn finney_config() -> Config {
        Config {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: "11".repeat(32),
            chain_spec_path: PathBuf::from("/tmp/umi-finney-raw-spec-da06f033.json"),
            chain_spec_sha256: FINNEY_CHAIN_SPEC_SHA256.to_owned(),
            expected_genesis_hash: FINNEY_GENESIS_HASH.to_owned(),
            bootstrap_block_number: 8_867_448,
            bootstrap_block_hash:
                "0x511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200".to_owned(),
            minimum_finalized_block: 8_867_449,
            maximum_records: 1,
            startup_timeout_seconds: 30,
            maximum_chain_spec_bytes: 16 * 1024 * 1024,
            maximum_header_bytes: 4096,
            maximum_ancestry_blocks: 128,
            maximum_record_bytes: 64 * 1024,
        }
    }

    fn finney_checkpoint() -> GrandpaWarpSyncCheckpoint {
        serde_json::from_value(finney_fixture()["checkpoint"].clone()).unwrap()
    }

    fn encode_compact(value: u64) -> Vec<u8> {
        if value < 1 << 6 {
            vec![(value as u8) << 2]
        } else if value < 1 << 14 {
            (((value as u16) << 2) | 1).to_le_bytes().to_vec()
        } else {
            (((value as u32) << 2) | 2).to_le_bytes().to_vec()
        }
    }

    fn header(number: u64, parent: [u8; 32], seed: u8) -> DecodedHeader {
        let mut bytes = Vec::new();
        bytes.extend(parent);
        bytes.extend(encode_compact(number));
        bytes.extend([seed; 32]);
        bytes.extend([seed.wrapping_add(1); 32]);
        bytes.push(0); // empty digest log vector
        decode_header(&format!("0x{}", hex::encode(bytes)), 4096).unwrap()
    }

    fn config() -> Config {
        Config {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: "11".repeat(32),
            chain_spec_path: PathBuf::from("/tmp/spec.json"),
            chain_spec_sha256: "22".repeat(32),
            expected_genesis_hash: format!("0x{}", "33".repeat(32)),
            bootstrap_block_number: 1,
            bootstrap_block_hash: format!("0x{}", "44".repeat(32)),
            minimum_finalized_block: 2,
            maximum_records: 10,
            startup_timeout_seconds: 30,
            maximum_chain_spec_bytes: 1024,
            maximum_header_bytes: 4096,
            maximum_ancestry_blocks: 128,
            maximum_record_bytes: 64 * 1024,
        }
    }

    fn ancestry(item: &DecodedHeader) -> AncestryEntry {
        AncestryEntry {
            number: item.number,
            hash: item.hash.clone(),
            parent_hash: item.parent_hash.clone(),
        }
    }

    #[test]
    fn malformed_header_is_rejected() {
        assert!(matches!(
            decode_header("0x00", 4096),
            Err(ObserverError::Protocol("truncated_header"))
        ));
        assert!(matches!(
            decode_header("00", 4096),
            Err(ObserverError::Protocol("header_missing_hex_prefix"))
        ));
    }

    #[test]
    fn transcript_rejects_rollback_and_gap() {
        let config = config();
        let first = header(10, [9; 32], 10);
        let mut transcript = Transcript::new(&config);
        transcript.set_startup_finalized_head(&first).unwrap();
        transcript
            .record(first.clone(), 1000, vec![ancestry(&first)], false)
            .unwrap();

        let rollback = header(9, [8; 32], 9);
        assert!(matches!(
            transcript.record(rollback.clone(), 1001, vec![ancestry(&rollback)], true),
            Err(ObserverError::Protocol("finality_rollback"))
        ));

        let gap = header(12, [11; 32], 12);
        assert!(matches!(
            transcript.record(gap.clone(), 1002, vec![ancestry(&gap)], true),
            Err(ObserverError::Protocol("ancestry_gap"))
        ));
    }

    #[test]
    fn transcript_hash_chain_and_contiguous_ancestry_are_stable() {
        let config = config();
        let first = header(10, [9; 32], 10);
        let second = header(
            11,
            blake2_256(&hex::decode(&first.scale_header[2..]).unwrap()),
            11,
        );
        let mut transcript = Transcript::new(&config);
        transcript.set_startup_finalized_head(&first).unwrap();
        let one = transcript
            .record(first.clone(), 1000, vec![ancestry(&first)], false)
            .unwrap();
        let two = transcript
            .record(second.clone(), 1001, vec![ancestry(&second)], true)
            .unwrap();
        assert_eq!(one.sequence, 0);
        assert_eq!(two.sequence, 1);
        assert_eq!(two.previous_transcript_digest, one.transcript_digest);
        assert_eq!(
            two.previous_finalized_hash.as_deref(),
            Some(first.hash.as_str())
        );
        assert!(two.ancestry_complete_since_previous);
    }

    #[test]
    fn genesis_bootstrap_is_rejected_by_config() {
        let mut config = config();
        config.bootstrap_block_number = 0;
        config.bootstrap_block_hash = config.expected_genesis_hash.clone();
        config.minimum_finalized_block = 1;
        assert!(matches!(
            config.validate(),
            Err(ObserverError::InvalidConfig("unsupported_bootstrap_source"))
        ));
    }

    #[test]
    fn startup_head_at_checkpoint_requires_the_exact_checkpoint_hash() {
        let mut config = config();
        let checkpoint = header(config.bootstrap_block_number, [0; 32], 1);
        let mut transcript = Transcript::new(&config);
        assert!(matches!(
            transcript.set_startup_finalized_head(&checkpoint),
            Err(ObserverError::Protocol("startup_checkpoint_hash_mismatch"))
        ));

        config.bootstrap_block_hash = checkpoint.hash.clone();
        let mut transcript = Transcript::new(&config);
        transcript.set_startup_finalized_head(&checkpoint).unwrap();
    }

    #[test]
    fn checkpoint_drift_is_rejected() {
        let mut config = finney_config();
        config.bootstrap_block_hash = format!("0x{}", "99".repeat(32));
        let spec = serde_json::json!({
            "grandpaWarpSyncCheckpoint": finney_fixture()["checkpoint"].clone()
        });
        assert!(matches!(
            prepare_chain_spec(&config, &serde_json::to_string(&spec).unwrap()),
            Err(ObserverError::InvalidChainSpec("checkpoint_drift"))
        ));
    }

    #[test]
    fn legacy_light_sync_state_is_rejected() {
        let config = finney_config();
        let spec = serde_json::json!({
            "lightSyncState": {"finalizedBlockHeader": finney_checkpoint().finalized_block_header}
        });
        assert!(matches!(
            prepare_chain_spec(&config, &serde_json::to_string(&spec).unwrap()),
            Err(ObserverError::InvalidChainSpec(
                "unsupported_legacy_bootstrap"
            ))
        ));
    }

    #[test]
    fn non_genesis_checkpoint_must_advance_before_emitting() {
        let mut config = finney_config();
        config.minimum_finalized_block = config.bootstrap_block_number;
        assert!(matches!(
            config.validate(),
            Err(ObserverError::InvalidConfig(
                "minimum_must_advance_checkpoint"
            ))
        ));
        config.minimum_finalized_block += 1;
        config.validate().unwrap();
    }

    #[test]
    fn finney_checkpoint_decodes_to_post_transition_consensus() {
        let config = finney_config();
        let information = checkpoint_chain_information(&config, &finney_checkpoint()).unwrap();
        let information = information.as_ref();
        assert_eq!(information.finalized_block_header.number, 8_867_448);
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(information.finalized_block_header.hash(BLOCK_NUMBER_BYTES))
            ),
            config.bootstrap_block_hash
        );
        match information.consensus {
            smoldot::chain::chain_information::ChainInformationConsensusRef::Aura {
                finalized_authorities_list,
                slot_duration,
            } => {
                assert_eq!(finalized_authorities_list.count(), 20);
                assert_eq!(slot_duration.get(), AURA_SLOT_DURATION_MS);
            }
            _ => panic!("Finney checkpoint must select Aura"),
        }
        match information.finality {
            smoldot::chain::chain_information::ChainInformationFinalityRef::Grandpa {
                after_finalized_block_authorities_set_id,
                finalized_triggered_authorities,
                finalized_scheduled_change,
            } => {
                assert_eq!(after_finalized_block_authorities_set_id, 6);
                assert_eq!(finalized_triggered_authorities.len(), 20);
                assert!(finalized_scheduled_change.is_none());
            }
            _ => panic!("Finney checkpoint must select GRANDPA"),
        }
    }

    #[test]
    fn finney_checkpoint_and_generated_database_are_hash_stable() {
        let config = finney_config();
        let fixture = finney_fixture();
        let spec = serde_json::json!({
            "name": "Bittensor",
            "id": "bittensor",
            "chainType": "Live",
            "bootNodes": [],
            "properties": {"ss58Format": 42, "tokenDecimals": 9, "tokenSymbol": "TAO"},
            "genesis": {
                "stateRootHash": "0x4015a36c6762db581cd56ec40af2a77ccd2a275fa96091358149d63293fc9643"
            },
            "grandpaWarpSyncCheckpoint": fixture["checkpoint"].clone(),
        });
        let material = prepare_chain_spec(&config, &serde_json::to_string(&spec).unwrap()).unwrap();
        let sanitized: Value = serde_json::from_str(&material.specification).unwrap();
        assert!(sanitized.get("grandpaWarpSyncCheckpoint").is_none());
        let database: Value = serde_json::from_str(&material.database_content).unwrap();
        assert_eq!(
            database["genesisHash"],
            Value::String(FINNEY_GENESIS_HASH.trim_start_matches("0x").to_owned())
        );
        let encoded_chain = serde_json::to_string(&database["chain"]).unwrap();
        let decoded = smoldot::database::finalized_serialize::decode_chain(
            &encoded_chain,
            BLOCK_NUMBER_BYTES,
        )
        .unwrap();
        assert_eq!(
            decoded
                .chain_information
                .as_ref()
                .finalized_block_header
                .number,
            config.bootstrap_block_number
        );
        assert_eq!(
            hex::encode(Sha256::digest(material.database_content.as_bytes())),
            FINNEY_BOOTSTRAP_DATABASE_SHA256
        );
    }

    #[tokio::test]
    async fn patched_light_client_accepts_generated_database_checkpoint() {
        let config = finney_config();
        let fixture = finney_fixture();
        let spec = serde_json::json!({
            "name": "Bittensor",
            "id": "bittensor",
            "chainType": "Live",
            "bootNodes": [],
            "properties": {"ss58Format": 42, "tokenDecimals": 9, "tokenSymbol": "TAO"},
            "genesis": {
                "stateRootHash": "0x4015a36c6762db581cd56ec40af2a77ccd2a275fa96091358149d63293fc9643"
            },
            "grandpaWarpSyncCheckpoint": fixture["checkpoint"].clone(),
        });
        let material = prepare_chain_spec(&config, &serde_json::to_string(&spec).unwrap()).unwrap();
        let expected_hash = decode_hash32(&config.bootstrap_block_hash).unwrap();
        let (_client, _rpc, receipt) = LightClient::relay_chain_with_database(
            material.specification.clone(),
            &material.database_content,
            config.bootstrap_block_number,
            expected_hash,
        )
        .unwrap();
        assert_eq!(receipt.block_number, config.bootstrap_block_number);
        assert_eq!(receipt.block_hash, expected_hash);
        assert!(
            LightClient::relay_chain_with_database(
                material.specification,
                &material.database_content,
                config.bootstrap_block_number + 1,
                expected_hash,
            )
            .is_err()
        );
    }

    #[test]
    fn finney_checkpoint_tampering_and_ambiguity_fail_closed() {
        let config = finney_config();

        let mut header_tamper = finney_checkpoint();
        let mut header = decode_checkpoint_hex(&header_tamper.finalized_block_header).unwrap();
        header[40] ^= 1;
        header_tamper.finalized_block_header = format!("0x{}", hex::encode(header));
        assert!(matches!(
            checkpoint_chain_information(&config, &header_tamper),
            Err(ObserverError::InvalidChainSpec("checkpoint_drift"))
        ));

        let mut authority_tamper = finney_checkpoint();
        let mut authorities =
            decode_checkpoint_hex(&authority_tamper.grandpa_authority_set).unwrap();
        let last_weight = authorities.len() - 8;
        authorities[last_weight..].fill(0);
        authority_tamper.grandpa_authority_set = format!("0x{}", hex::encode(authorities));
        assert!(matches!(
            checkpoint_chain_information(&config, &authority_tamper),
            Err(ObserverError::InvalidChainSpec(
                "zero_checkpoint_authority_weight"
            ))
        ));

        let fixture = finney_fixture();
        let ambiguous = serde_json::json!({
            "lightSyncState": {"finalizedBlockHeader": fixture["checkpoint"]["finalizedBlockHeader"]},
            "grandpaWarpSyncCheckpoint": fixture["checkpoint"].clone(),
        });
        assert!(matches!(
            prepare_chain_spec(&config, &serde_json::to_string(&ambiguous).unwrap()),
            Err(ObserverError::InvalidChainSpec(
                "ambiguous_checkpoint_profiles"
            ))
        ));
    }

    #[test]
    fn chain_spec_symlink_is_rejected() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let directory = std::env::temp_dir().join(format!(
                "umi-finality-test-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("unnamed")
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(&directory).unwrap();
            let target = directory.join("target.json");
            let link = directory.join("link.json");
            fs::File::create(&target).unwrap().write_all(b"{}").unwrap();
            symlink(&target, &link).unwrap();
            let mut config = config();
            config.chain_spec_path = link;
            config.chain_spec_sha256 = hex::encode(Sha256::digest(b"{}"));
            assert!(matches!(
                read_chain_spec(&config),
                Err(ObserverError::InvalidChainSpec("unsafe_chain_spec_path"))
            ));
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn pinned_fixture_headers_decode_exactly() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/finality-v1.json")).unwrap();
        assert_eq!(
            fixture["schema"],
            Value::String("umi-grandpa-finality-fixtures/1".to_owned())
        );
        for name in ["first", "second"] {
            let expected = &fixture["valid_contiguous"][name];
            let decoded = decode_header(expected["scale_header"].as_str().unwrap(), 4096).unwrap();
            assert_eq!(decoded.number, expected["number"].as_u64().unwrap());
            assert_eq!(decoded.hash, expected["hash"].as_str().unwrap());
        }
        let checkpoint = &fixture["checkpoint"];
        let decoded = decode_header(checkpoint["scale_header"].as_str().unwrap(), 4096).unwrap();
        assert_eq!(decoded.number, checkpoint["number"].as_u64().unwrap());
        assert_eq!(decoded.hash, checkpoint["hash"].as_str().unwrap());
        for malformed in fixture["malformed_headers"].as_array().unwrap() {
            assert!(decode_header(malformed.as_str().unwrap(), 4096).is_err());
        }
    }
}
