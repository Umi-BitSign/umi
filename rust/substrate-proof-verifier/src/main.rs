// Copyright 2026 UMI contributors
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};

use serde::{Deserialize, Serialize};
use sp_core::{Blake2Hasher, H256};
use sp_trie::{LayoutV1, StorageProof, Trie, TrieConfiguration, TrieDBBuilder};

const REQUEST_SCHEMA: &str = "umi-substrate-proof/1";
const EXTRINSICS_ROOT_REQUEST_SCHEMA: &str = "umi-substrate-extrinsics-root/1";
const RESPONSE_SCHEMA: &str = "umi-substrate-proof-result/1";
const READ_REQUEST_SCHEMA: &str = "umi-substrate-proof-read/1";
const READ_RESPONSE_SCHEMA: &str = "umi-substrate-proof-values/1";
const MAX_LINE_BYTES: usize = 160 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_ITEMS: usize = 4_096;
const MAX_KEY_BYTES: usize = 512;
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_READ_VALUES_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROOF_NODES: usize = 4_096;
// LayoutV1 stores large values as separate, raw proof nodes. A proof of any
// permitted value (including :code) must fit; the total proof cap stays 32 MiB.
const MAX_PROOF_NODE_BYTES: usize = MAX_VALUE_BYTES;
const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;
const MAX_EXTRINSICS: usize = 4_096;
const MAX_EXTRINSIC_BYTES: usize = 16 * 1024 * 1024;
const MAX_BLOCK_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofRequest {
    schema: String,
    request_id: String,
    state_version: u8,
    state_root: String,
    items: Vec<ProofItem>,
    proof: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtrinsicsRootRequest {
    schema: String,
    request_id: String,
    state_version: u8,
    expected_root: String,
    extrinsics: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    schema: String,
    request_id: String,
    state_version: u8,
    state_root: String,
    keys: Vec<String>,
    proof: Vec<String>,
    maximum_value_bytes: usize,
    maximum_total_value_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VerificationRequest {
    StorageProof(ProofRequest),
    ExtrinsicsRoot(ExtrinsicsRootRequest),
    ReadProof(ReadRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofItem {
    key: String,
    value: ClaimedValue,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ClaimedValue {
    Present(String),
    Absent(()),
}

#[derive(Debug, Serialize)]
struct ProofResponse {
    schema: &'static str,
    request_id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    values: Option<ProofValues>,
}

#[derive(Debug, Serialize)]
struct ProofValues {
    state_version: u8,
    state_root: String,
    items: Vec<ReadValue>,
}

#[derive(Debug, Serialize)]
struct ReadValue {
    key: String,
    value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationError {
    InvalidInput,
    UnsupportedStateVersion,
    DuplicateNode,
    InvalidProof,
    InvalidExtrinsicsRoot,
    ValueLimit,
}

impl VerificationError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::UnsupportedStateVersion => "unsupported_state_version",
            Self::DuplicateNode => "duplicate_node",
            Self::InvalidProof => "invalid_proof",
            Self::InvalidExtrinsicsRoot => "invalid_extrinsics_root",
            Self::ValueLimit => "value_limit",
        }
    }
}

fn validate_request_id(value: &str) -> Result<(), VerificationError> {
    if value.is_empty() || value.len() > MAX_REQUEST_ID_BYTES || !value.is_ascii() {
        return Err(VerificationError::InvalidInput);
    }
    Ok(())
}

fn decode_hex(
    value: &str,
    maximum_bytes: usize,
    allow_empty: bool,
) -> Result<Vec<u8>, VerificationError> {
    let Some(encoded) = value.strip_prefix("0x") else {
        return Err(VerificationError::InvalidInput);
    };
    if (!allow_empty && encoded.is_empty())
        || encoded.len() % 2 != 0
        || encoded.len() / 2 > maximum_bytes
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VerificationError::InvalidInput);
    }
    hex::decode(encoded).map_err(|_| VerificationError::InvalidInput)
}

fn verify_request(request: &ProofRequest) -> Result<(), VerificationError> {
    if request.schema != REQUEST_SCHEMA
        || request.items.is_empty()
        || request.items.len() > MAX_ITEMS
        || request.proof.is_empty()
        || request.proof.len() > MAX_PROOF_NODES
    {
        return Err(VerificationError::InvalidInput);
    }
    validate_request_id(&request.request_id)?;
    if request.state_version != 1 {
        return Err(VerificationError::UnsupportedStateVersion);
    }

    let root_bytes = decode_hex(&request.state_root, 32, false)?;
    if root_bytes.len() != 32 {
        return Err(VerificationError::InvalidInput);
    }
    let root = H256::from_slice(&root_bytes);

    let mut items = Vec::with_capacity(request.items.len());
    let mut previous_key: Option<Vec<u8>> = None;
    for item in &request.items {
        let key = decode_hex(&item.key, MAX_KEY_BYTES, false)?;
        if key.is_empty()
            || previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
        {
            return Err(VerificationError::InvalidInput);
        }
        let value = match &item.value {
            ClaimedValue::Present(encoded) => Some(decode_hex(encoded, MAX_VALUE_BYTES, true)?),
            ClaimedValue::Absent(()) => None,
        };
        previous_key = Some(key.clone());
        items.push((key, value));
    }

    let database = proof_database(&request.proof)?;
    let trie = TrieDBBuilder::<LayoutV1<Blake2Hasher>>::new(&database, &root).build();
    for (key, expected) in items {
        let actual = trie
            .get(&key)
            .map_err(|_| VerificationError::InvalidProof)?;
        if actual != expected {
            return Err(VerificationError::InvalidProof);
        }
    }
    Ok(())
}

fn proof_database(
    encoded_nodes: &[String],
) -> Result<sp_trie::MemoryDB<Blake2Hasher>, VerificationError> {
    if encoded_nodes.is_empty() || encoded_nodes.len() > MAX_PROOF_NODES {
        return Err(VerificationError::InvalidInput);
    }
    let mut proof_bytes = 0usize;
    let mut proof_nodes = Vec::with_capacity(encoded_nodes.len());
    for encoded in encoded_nodes {
        let node = decode_hex(encoded, MAX_PROOF_NODE_BYTES, false)?;
        if node.is_empty() {
            return Err(VerificationError::InvalidInput);
        }
        proof_bytes = proof_bytes
            .checked_add(node.len())
            .ok_or(VerificationError::InvalidInput)?;
        if proof_bytes > MAX_PROOF_BYTES {
            return Err(VerificationError::InvalidInput);
        }
        proof_nodes.push(node);
    }

    let proof = StorageProof::new_with_duplicate_nodes_check(proof_nodes)
        .map_err(|_| VerificationError::DuplicateNode)?;
    // `state_getReadProof` returns the raw encoded nodes of a `StorageProof`.
    // `verify_trie_proof` accepts a different, compact path-proof encoding produced by
    // `generate_trie_proof`; feeding raw RPC nodes to it rejects valid network proofs. Rebuild
    // the partial trie exactly as `sp_state_machine::read_proof_check` does and perform every
    // lookup against the claimed state root. A missing node makes `Trie::get` fail rather than
    // turning an incomplete proof into a false non-membership result.
    Ok(proof.into_memory_db::<Blake2Hasher>())
}

fn read_request(request: &ReadRequest) -> Result<ProofValues, VerificationError> {
    if request.schema != READ_REQUEST_SCHEMA
        || request.keys.is_empty()
        || request.keys.len() > MAX_ITEMS
        || request.maximum_value_bytes == 0
        || request.maximum_value_bytes > MAX_VALUE_BYTES
        || request.maximum_total_value_bytes == 0
        || request.maximum_total_value_bytes > MAX_READ_VALUES_BYTES
    {
        return Err(VerificationError::InvalidInput);
    }
    validate_request_id(&request.request_id)?;
    if request.state_version != 1 {
        return Err(VerificationError::UnsupportedStateVersion);
    }
    let root_bytes = decode_hex(&request.state_root, 32, false)?;
    if root_bytes.len() != 32 {
        return Err(VerificationError::InvalidInput);
    }
    let root = H256::from_slice(&root_bytes);
    let database = proof_database(&request.proof)?;
    let trie = TrieDBBuilder::<LayoutV1<Blake2Hasher>>::new(&database, &root).build();
    let mut previous_key: Option<Vec<u8>> = None;
    let mut items = Vec::with_capacity(request.keys.len());
    let mut total_bytes = 0usize;
    for encoded in &request.keys {
        let key = decode_hex(encoded, MAX_KEY_BYTES, false)?;
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(VerificationError::InvalidInput);
        }
        let value = trie
            .get(&key)
            .map_err(|_| VerificationError::InvalidProof)?;
        if let Some(ref value) = value {
            total_bytes = total_bytes
                .checked_add(value.len())
                .ok_or(VerificationError::ValueLimit)?;
            if value.len() > request.maximum_value_bytes
                || total_bytes > request.maximum_total_value_bytes
            {
                return Err(VerificationError::ValueLimit);
            }
        }
        items.push(ReadValue {
            key: encoded.clone(),
            value: value.map(|bytes| format!("0x{}", hex::encode(bytes))),
        });
        previous_key = Some(key);
    }
    // No partially checked items are emitted if any later lookup or bound fails.
    Ok(ProofValues {
        state_version: 1,
        state_root: request.state_root.clone(),
        items,
    })
}

fn verify_extrinsics_root(request: &ExtrinsicsRootRequest) -> Result<(), VerificationError> {
    if request.schema != EXTRINSICS_ROOT_REQUEST_SCHEMA || request.extrinsics.len() > MAX_EXTRINSICS
    {
        return Err(VerificationError::InvalidInput);
    }
    validate_request_id(&request.request_id)?;
    if request.state_version != 1 {
        return Err(VerificationError::UnsupportedStateVersion);
    }
    let expected_bytes = decode_hex(&request.expected_root, 32, false)?;
    if expected_bytes.len() != 32 {
        return Err(VerificationError::InvalidInput);
    }
    let mut total_bytes = 0usize;
    let mut extrinsics = Vec::with_capacity(request.extrinsics.len());
    for encoded in &request.extrinsics {
        let extrinsic = decode_hex(encoded, MAX_EXTRINSIC_BYTES, false)?;
        total_bytes = total_bytes
            .checked_add(extrinsic.len())
            .ok_or(VerificationError::InvalidInput)?;
        if total_bytes > MAX_BLOCK_BODY_BYTES {
            return Err(VerificationError::InvalidInput);
        }
        extrinsics.push(extrinsic);
    }
    let actual = LayoutV1::<Blake2Hasher>::ordered_trie_root(extrinsics.iter());
    if actual.as_bytes() != expected_bytes.as_slice() {
        return Err(VerificationError::InvalidExtrinsicsRoot);
    }
    Ok(())
}

fn response_for_line(line: &[u8]) -> ProofResponse {
    let Ok(request) = serde_json::from_slice::<VerificationRequest>(line) else {
        return ProofResponse {
            schema: RESPONSE_SCHEMA,
            request_id: String::new(),
            ok: false,
            error_code: Some(VerificationError::InvalidInput.code()),
            values: None,
        };
    };
    let (request_id, result) = match &request {
        VerificationRequest::StorageProof(value) => {
            (value.request_id.clone(), verify_request(value))
        }
        VerificationRequest::ExtrinsicsRoot(value) => {
            (value.request_id.clone(), verify_extrinsics_root(value))
        }
        VerificationRequest::ReadProof(value) => {
            return match read_request(value) {
                Ok(values) => ProofResponse {
                    schema: READ_RESPONSE_SCHEMA,
                    request_id: value.request_id.clone(),
                    ok: true,
                    error_code: None,
                    values: Some(values),
                },
                Err(error) => ProofResponse {
                    schema: READ_RESPONSE_SCHEMA,
                    request_id: value.request_id.clone(),
                    ok: false,
                    error_code: Some(error.code()),
                    values: None,
                },
            };
        }
    };
    match result {
        Ok(()) => ProofResponse {
            schema: RESPONSE_SCHEMA,
            request_id,
            ok: true,
            error_code: None,
            values: None,
        },
        Err(error) => ProofResponse {
            schema: RESPONSE_SCHEMA,
            request_id,
            ok: false,
            error_code: Some(error.code()),
            values: None,
        },
    }
}

enum LineRead {
    Eof,
    Line,
    TooLong,
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    output: &mut Vec<u8>,
    maximum_bytes: usize,
) -> io::Result<LineRead> {
    output.clear();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if output.is_empty() && !too_long {
                return Ok(LineRead::Eof);
            }
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let content_len = newline.unwrap_or(available.len());
        if !too_long {
            if output.len().saturating_add(content_len) > maximum_bytes {
                output.clear();
                too_long = true;
            } else {
                output.extend_from_slice(&available[..content_len]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            if output.last() == Some(&b'\r') {
                output.pop();
            }
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
    }
}

fn write_response<W: Write>(writer: &mut W, response: &ProofResponse) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn run<R: Read, W: Write>(input: R, output: W) -> io::Result<()> {
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut line = Vec::new();
    loop {
        match read_bounded_line(&mut reader, &mut line, MAX_LINE_BYTES)? {
            LineRead::Eof => return Ok(()),
            LineRead::Line => write_response(&mut writer, &response_for_line(&line))?,
            LineRead::TooLong => write_response(
                &mut writer,
                &ProofResponse {
                    schema: RESPONSE_SCHEMA,
                    request_id: String::new(),
                    ok: false,
                    error_code: Some(VerificationError::InvalidInput.code()),
                    values: None,
                },
            )?,
        }
    }
}

fn main() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "umi-substrate-proof-verifier accepts no command-line arguments",
        ));
    }
    run(io::stdin().lock(), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use sp_trie::{MemoryDB, Recorder, TrieDBMutBuilder, TrieMut, generate_trie_proof};

    type Layout = LayoutV1<Blake2Hasher>;

    fn fixture() -> (H256, Vec<Vec<u8>>) {
        let (mut database, mut root) = MemoryDB::<Blake2Hasher>::default_with_root();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut database, &mut root).build();
            trie.insert(b"alpha", b"one").expect("insert must succeed");
            trie.insert(b"beta", b"two").expect("insert must succeed");
        }
        let mut recorder = Recorder::<Layout>::new();
        {
            let trie = TrieDBBuilder::<Layout>::new(&database, &root)
                .with_recorder(&mut recorder)
                .build();
            trie.get(b"alpha").expect("membership lookup must succeed");
            trie.get(b"missing")
                .expect("non-membership lookup must succeed");
        }
        let proof = StorageProof::new(recorder.drain().into_iter().map(|record| record.data))
            .into_iter_nodes()
            .collect();
        (root, proof)
    }

    fn request(root: H256, proof: &[Vec<u8>]) -> ProofRequest {
        ProofRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: "fixture".to_owned(),
            state_version: 1,
            state_root: format!("0x{}", hex::encode(root.as_bytes())),
            items: vec![
                ProofItem {
                    key: format!("0x{}", hex::encode(b"alpha")),
                    value: ClaimedValue::Present(format!("0x{}", hex::encode(b"one"))),
                },
                ProofItem {
                    key: format!("0x{}", hex::encode(b"missing")),
                    value: ClaimedValue::Absent(()),
                },
            ],
            proof: proof
                .iter()
                .map(|node| format!("0x{}", hex::encode(node)))
                .collect(),
        }
    }

    fn finney_checkpoint_request() -> ProofRequest {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/finney-state-v1.json"))
            .expect("checked-in Finney fixture must be valid JSON");
        assert_eq!(fixture["schema"], "umi-substrate-proof-fixture/1");
        assert_eq!(fixture["block_number"], 8_867_448);
        assert_eq!(
            fixture["block_hash"],
            "0x511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200"
        );
        serde_json::from_value(json!({
            "schema": REQUEST_SCHEMA,
            "request_id": "finney-checkpoint-aura-authorities",
            "state_version": fixture["state_version"],
            "state_root": fixture["state_root"],
            "items": fixture["items"],
            "proof": fixture["proof"],
        }))
        .expect("checked-in Finney fixture must form a proof request")
    }

    fn read_from(request: &ProofRequest) -> ReadRequest {
        ReadRequest {
            schema: READ_REQUEST_SCHEMA.to_owned(),
            request_id: "read-fixture".to_owned(),
            state_version: request.state_version,
            state_root: request.state_root.clone(),
            keys: request.items.iter().map(|item| item.key.clone()).collect(),
            proof: request.proof.clone(),
            maximum_value_bytes: MAX_VALUE_BYTES,
            maximum_total_value_bytes: MAX_READ_VALUES_BYTES,
        }
    }

    fn read_wire(request: &ReadRequest) -> Value {
        let raw = serde_json::to_vec(&json!({
            "schema": request.schema, "request_id": request.request_id,
            "state_version": request.state_version, "state_root": request.state_root,
            "keys": request.keys, "proof": request.proof,
            "maximum_value_bytes": request.maximum_value_bytes,
            "maximum_total_value_bytes": request.maximum_total_value_bytes,
        }))
        .unwrap();
        serde_json::to_value(response_for_line(&raw)).unwrap()
    }

    #[test]
    fn extracts_real_finney_proof_values_without_claims() {
        let original = finney_checkpoint_request();
        let response = read_wire(&read_from(&original));
        assert_eq!(response["ok"], true);
        assert_eq!(response["schema"], READ_RESPONSE_SCHEMA);
        assert_eq!(response["request_id"], "read-fixture");
        assert_eq!(response["state_root"], original.state_root);
        assert_eq!(response["state_version"], 1);
        for (actual, expected) in response["items"]
            .as_array()
            .unwrap()
            .iter()
            .zip(original.items)
        {
            assert_eq!(actual["key"], expected.key);
            let value = match expected.value {
                ClaimedValue::Present(encoded) => json!(encoded),
                ClaimedValue::Absent(()) => Value::Null,
            };
            assert_eq!(actual["value"], value);
        }
    }

    #[test]
    fn extracts_absence_and_empty_values_distinctly() {
        let (mut database, mut root) = MemoryDB::<Blake2Hasher>::default_with_root();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut database, &mut root).build();
            trie.insert(b"empty", b"").unwrap();
        }
        let mut recorder = Recorder::<Layout>::new();
        {
            let trie = TrieDBBuilder::<Layout>::new(&database, &root)
                .with_recorder(&mut recorder)
                .build();
            assert_eq!(trie.get(b"empty").unwrap(), Some(Vec::new()));
            assert_eq!(trie.get(b"missing").unwrap(), None);
        }
        let nodes: Vec<Vec<u8>> = StorageProof::new(recorder.drain().into_iter().map(|r| r.data))
            .into_iter_nodes()
            .collect();
        let mut read = read_from(&request(root, &nodes));
        read.keys = vec![
            format!("0x{}", hex::encode(b"empty")),
            format!("0x{}", hex::encode(b"missing")),
        ];
        let response = read_wire(&read);
        assert_eq!(response["ok"], true);
        assert_eq!(response["items"][0]["value"], "0x");
        assert_eq!(response["items"][1]["value"], Value::Null);
    }

    #[test]
    fn read_failures_never_return_partial_values() {
        let (root, proof) = fixture();
        for change in 0..9 {
            let mut read = read_from(&request(root, &proof));
            match change {
                0 => read.state_root = format!("0x{}", "00".repeat(32)),
                1 => read.proof.push(read.proof[0].clone()),
                2 => read.keys.push(read.keys[0].clone()),
                3 => read.keys.reverse(),
                4 => read.state_version = 2,
                5 => read.maximum_value_bytes = 2,
                6 => read.maximum_total_value_bytes = 2,
                7 => read.keys.push("0xzz".to_owned()),
                _ => read.maximum_total_value_bytes = MAX_READ_VALUES_BYTES + 1,
            }
            let response = read_wire(&read);
            assert_eq!(response["ok"], false, "change {change}");
            assert!(response.get("items").is_none());
            assert!(response.get("state_root").is_none());
            assert!(response.get("error_code").is_some());
        }
    }

    #[test]
    fn reads_external_values_and_rejects_missing_or_changed_nodes() {
        let original = large_value_request(1024 * 1024);
        let read = read_from(&original);
        assert_eq!(
            read_wire(&read)["items"][0]["value"],
            format!("0x{}", "5a".repeat(1024 * 1024))
        );
        for missing in [false, true] {
            let mut changed = read_from(&original);
            let index = changed
                .proof
                .iter()
                .position(|node| node.len() > 1024 * 1024)
                .unwrap();
            if missing {
                changed.proof.remove(index);
            } else {
                changed.proof[index].replace_range(2..4, "00");
            }
            let response = read_wire(&changed);
            assert_eq!(response["ok"], false);
            assert_eq!(response["error_code"], "invalid_proof");
            assert!(response.get("items").is_none());
        }
    }

    #[test]
    fn aggregate_read_limit_applies_to_repeated_value_content() {
        let (mut database, mut root) = MemoryDB::<Blake2Hasher>::default_with_root();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut database, &mut root).build();
            trie.insert(b"alpha", b"same").unwrap();
            trie.insert(b"beta", b"same").unwrap();
        }
        let mut recorder = Recorder::<Layout>::new();
        {
            let trie = TrieDBBuilder::<Layout>::new(&database, &root)
                .with_recorder(&mut recorder)
                .build();
            trie.get(b"alpha").unwrap();
            trie.get(b"beta").unwrap();
        }
        let nodes: Vec<Vec<u8>> = StorageProof::new(recorder.drain().into_iter().map(|r| r.data))
            .into_iter_nodes()
            .collect();
        let mut read = read_from(&request(root, &nodes));
        read.keys = vec![
            format!("0x{}", hex::encode(b"alpha")),
            format!("0x{}", hex::encode(b"beta")),
        ];
        read.maximum_value_bytes = 4;
        read.maximum_total_value_bytes = 7;
        let response = read_wire(&read);
        assert_eq!(response["ok"], false);
        assert_eq!(response["error_code"], "value_limit");
        assert!(response.get("items").is_none());
        read.maximum_total_value_bytes = 8;
        assert_eq!(read_wire(&read)["ok"], true);
    }

    #[test]
    fn verifies_membership_and_non_membership_together() {
        let (root, proof) = fixture();
        assert_eq!(verify_request(&request(root, &proof)), Ok(()));
    }

    fn large_value_request(size: usize) -> ProofRequest {
        let value = vec![0x5a; size];
        let (mut database, mut root) = MemoryDB::<Blake2Hasher>::default_with_root();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut database, &mut root).build();
            trie.insert(b":code", &value).expect("insert must succeed");
        }
        let mut recorder = Recorder::<Layout>::new();
        {
            let trie = TrieDBBuilder::<Layout>::new(&database, &root)
                .with_recorder(&mut recorder)
                .build();
            assert_eq!(
                trie.get(b":code").expect("lookup must succeed"),
                Some(value.clone())
            );
        }
        let proof: Vec<Vec<u8>> =
            StorageProof::new(recorder.drain().into_iter().map(|record| record.data))
                .into_iter_nodes()
                .collect();
        // The value itself is a raw proof node, not a compact path-proof value.
        assert!(proof.contains(&value));
        let mut result = request(root, &proof);
        result.items = vec![ProofItem {
            key: format!("0x{}", hex::encode(b":code")),
            value: ClaimedValue::Present(format!("0x{}", hex::encode(value))),
        }];
        result
    }

    #[test]
    fn verifies_large_external_values_and_rejects_tampering() {
        for size in [3 * 1024 * 1024, MAX_VALUE_BYTES] {
            let mut request = large_value_request(size);
            assert_eq!(verify_request(&request), Ok(()));
            let index = request
                .proof
                .iter()
                .position(|node| node.len() == 2 + size * 2)
                .expect("external value node must exist");
            let original = request.proof[index].pop().expect("value must not be empty");
            request.proof[index].push('0');
            assert_eq!(
                verify_request(&request),
                Err(VerificationError::InvalidProof)
            );
            request.proof[index].pop();
            request.proof[index].push(original);
            request.proof.remove(index);
            assert_eq!(
                verify_request(&request),
                Err(VerificationError::InvalidProof)
            );
        }
    }

    #[test]
    fn large_nodes_still_obey_individual_and_total_caps() {
        let (root, proof) = fixture();
        let mut oversized_node = request(root, &proof);
        oversized_node
            .proof
            .push(format!("0x{}", "00".repeat(MAX_PROOF_NODE_BYTES + 1)));
        assert_eq!(
            verify_request(&oversized_node),
            Err(VerificationError::InvalidInput)
        );
        drop(oversized_node);

        let mut oversized_total = request(root, &proof);
        for byte in ["01", "02"] {
            oversized_total
                .proof
                .push(format!("0x{}", byte.repeat(MAX_PROOF_NODE_BYTES)));
        }
        assert_eq!(
            verify_request(&oversized_total),
            Err(VerificationError::InvalidInput)
        );
    }

    #[test]
    fn verifies_real_finney_state_v1_rpc_storage_proof() {
        assert_eq!(verify_request(&finney_checkpoint_request()), Ok(()));
    }

    #[test]
    fn rejects_tampered_real_finney_rpc_storage_proof() {
        let mut wrong_value = finney_checkpoint_request();
        wrong_value.items[0].value = ClaimedValue::Present("0x00".to_owned());
        assert_eq!(
            verify_request(&wrong_value),
            Err(VerificationError::InvalidProof)
        );

        let mut missing_node = finney_checkpoint_request();
        missing_node.proof.pop();
        assert_eq!(
            verify_request(&missing_node),
            Err(VerificationError::InvalidProof)
        );

        let mut changed_node = finney_checkpoint_request();
        let last = changed_node.proof[0]
            .pop()
            .expect("fixture proof node must not be empty");
        changed_node.proof[0].push(if last == '0' { '1' } else { '0' });
        assert_eq!(
            verify_request(&changed_node),
            Err(VerificationError::InvalidProof)
        );
    }

    #[test]
    fn rejects_compact_path_proof_at_raw_storage_proof_boundary() {
        let (mut database, mut root) = MemoryDB::<Blake2Hasher>::default_with_root();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut database, &mut root).build();
            trie.insert(b"alpha", b"one").expect("insert must succeed");
            trie.insert(b"beta", b"two").expect("insert must succeed");
        }
        let keys = [b"alpha".to_vec(), b"missing".to_vec()];
        let compact = generate_trie_proof::<Layout, _, _, _>(&database, root, keys.iter())
            .expect("compact proof generation must succeed");

        assert_eq!(
            verify_request(&request(root, &compact)),
            Err(VerificationError::InvalidProof)
        );
    }

    #[test]
    fn rejects_wrong_value_and_root() {
        let (root, proof) = fixture();
        let mut wrong_value = request(root, &proof);
        wrong_value.items[0].value = ClaimedValue::Present("0x77726f6e67".to_owned());
        assert_eq!(
            verify_request(&wrong_value),
            Err(VerificationError::InvalidProof)
        );

        let mut wrong_root = request(root, &proof);
        wrong_root.state_root = format!("0x{}", "00".repeat(32));
        assert_eq!(
            verify_request(&wrong_root),
            Err(VerificationError::InvalidProof)
        );
    }

    #[test]
    fn verifies_ordered_extrinsics_root_and_rejects_mismatch() {
        let extrinsics = [b"first-extrinsic".to_vec(), b"second-extrinsic".to_vec()];
        let root = LayoutV1::<Blake2Hasher>::ordered_trie_root(extrinsics.iter());
        let mut request = ExtrinsicsRootRequest {
            schema: EXTRINSICS_ROOT_REQUEST_SCHEMA.to_owned(),
            request_id: "fixture-root".to_owned(),
            state_version: 1,
            expected_root: format!("0x{}", hex::encode(root.as_bytes())),
            extrinsics: extrinsics
                .iter()
                .map(|value| format!("0x{}", hex::encode(value)))
                .collect(),
        };
        assert_eq!(verify_extrinsics_root(&request), Ok(()));

        request.expected_root = format!("0x{}", "00".repeat(32));
        assert_eq!(
            verify_extrinsics_root(&request),
            Err(VerificationError::InvalidExtrinsicsRoot)
        );
    }

    #[test]
    fn verifies_empty_ordered_extrinsics_root() {
        let extrinsics: Vec<Vec<u8>> = Vec::new();
        let root = LayoutV1::<Blake2Hasher>::ordered_trie_root(extrinsics.iter());
        let request = ExtrinsicsRootRequest {
            schema: EXTRINSICS_ROOT_REQUEST_SCHEMA.to_owned(),
            request_id: "empty-root".to_owned(),
            state_version: 1,
            expected_root: format!("0x{}", hex::encode(root.as_bytes())),
            extrinsics: Vec::new(),
        };
        assert_eq!(verify_extrinsics_root(&request), Ok(()));
    }

    #[test]
    fn rejects_duplicate_nodes_before_verification() {
        let (root, mut proof) = fixture();
        proof.push(proof[0].clone());
        assert_eq!(
            verify_request(&request(root, &proof)),
            Err(VerificationError::DuplicateNode)
        );
    }

    #[test]
    fn rejects_unsorted_or_duplicate_keys_and_noncanonical_hex() {
        let (root, proof) = fixture();
        let mut unsorted = request(root, &proof);
        unsorted.items.swap(0, 1);
        assert_eq!(
            verify_request(&unsorted),
            Err(VerificationError::InvalidInput)
        );

        let mut duplicate = request(root, &proof);
        duplicate.items[1].key = duplicate.items[0].key.clone();
        assert_eq!(
            verify_request(&duplicate),
            Err(VerificationError::InvalidInput)
        );

        let mut uppercase = request(root, &proof);
        uppercase.state_root = uppercase.state_root.to_uppercase();
        assert_eq!(
            verify_request(&uppercase),
            Err(VerificationError::InvalidInput)
        );
    }

    #[test]
    fn value_member_is_required_and_must_be_hex_or_null() {
        for item in [
            serde_json::json!({"key": "0x61"}),
            serde_json::json!({"key": "0x61", "value": 7}),
        ] {
            let encoded = serde_json::to_vec(&serde_json::json!({
                "schema": REQUEST_SCHEMA,
                "request_id": "strict-value",
                "state_version": 1,
                "state_root": format!("0x{}", "00".repeat(32)),
                "items": [item],
                "proof": ["0x01"]
            }))
            .expect("request serialization must succeed");
            let response = response_for_line(&encoded);
            assert!(!response.ok);
            assert_eq!(response.error_code, Some("invalid_input"));
        }
        assert_eq!(decode_hex("0x", MAX_VALUE_BYTES, true), Ok(Vec::new()));
    }

    #[test]
    fn ndjson_loop_returns_one_bounded_response_per_line() {
        let (root, proof) = fixture();
        let valid = serde_json::to_vec(&serde_json::json!({
            "schema": REQUEST_SCHEMA,
            "request_id": "first",
            "state_version": 1,
            "state_root": format!("0x{}", hex::encode(root.as_bytes())),
            "items": [
                {"key": format!("0x{}", hex::encode(b"alpha")), "value": format!("0x{}", hex::encode(b"one"))},
                {"key": format!("0x{}", hex::encode(b"missing")), "value": null}
            ],
            "proof": proof.iter().map(|node| format!("0x{}", hex::encode(node))).collect::<Vec<_>>()
        }))
        .expect("request serialization must succeed");
        let mut input = valid;
        input.extend_from_slice(b"\nnot-json\n");
        let mut output = Vec::new();
        run(input.as_slice(), &mut output).expect("NDJSON run must succeed");
        let lines: Vec<&[u8]> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_slice(lines[0]).expect("valid response");
        let second: serde_json::Value = serde_json::from_slice(lines[1]).expect("valid response");
        assert_eq!(first["ok"], true);
        assert_eq!(first["request_id"], "first");
        assert_eq!(second["ok"], false);
        assert_eq!(second["error_code"], "invalid_input");
    }

    #[test]
    fn oversized_line_is_drained_without_consuming_the_next_request() {
        let input = b"12345\nnext\n";
        let mut reader = BufReader::new(input.as_slice());
        let mut line = Vec::new();
        assert!(matches!(
            read_bounded_line(&mut reader, &mut line, 4),
            Ok(LineRead::TooLong)
        ));
        assert!(line.is_empty());
        assert!(matches!(
            read_bounded_line(&mut reader, &mut line, 4),
            Ok(LineRead::Line)
        ));
        assert_eq!(line, b"next");
    }
}
