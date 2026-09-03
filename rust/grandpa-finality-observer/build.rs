use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const VENDOR_HASH_DOMAIN: &[u8] = b"umi-grandpa-finality-vendor-v1\0";
const EXPECTED_VENDOR_TREE_SHA256: &str =
    "6ebb7bb6f4c5bbf559fe09e27996382eb44ff81e0b68105cb7755a5ca56d37be";
const EXPECTED_FINNEY_CHECKPOINT_FIXTURE_SHA256: &str =
    "b3f2191587a21b57fbe9f56e3a8245e852c06cdebb0a4dd0b878a5242d9a8311";

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("cannot read vendored directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()));
        if metadata.file_type().is_symlink() {
            panic!("vendored source contains a symlink: {}", path.display());
        }
        if metadata.is_dir() {
            collect_files(root, &path, files);
        } else if metadata.is_file() {
            files.push(
                path.strip_prefix(root)
                    .expect("file is below vendor root")
                    .to_owned(),
            );
        } else {
            panic!(
                "vendored source contains a special file: {}",
                path.display()
            );
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    let vendor_root = manifest_dir.join("vendor");
    println!("cargo:rerun-if-changed={}", vendor_root.display());

    let mut files = Vec::new();
    collect_files(&vendor_root, &vendor_root, &mut files);
    files.sort_by_key(|path| {
        path.to_str()
            .expect("vendored paths are UTF-8")
            .replace(std::path::MAIN_SEPARATOR, "/")
    });
    let file_count = u32::try_from(files.len()).expect("vendor tree has at most u32 files");

    let mut tree = Sha256::new();
    tree.update(VENDOR_HASH_DOMAIN);
    tree.update(file_count.to_be_bytes());
    for relative in files {
        let relative = relative
            .to_str()
            .expect("vendored paths are UTF-8")
            .replace(std::path::MAIN_SEPARATOR, "/");
        let relative_bytes = relative.as_bytes();
        tree.update(
            u32::try_from(relative_bytes.len())
                .expect("vendored path length fits u32")
                .to_be_bytes(),
        );
        tree.update(relative_bytes);
        let bytes = fs::read(vendor_root.join(&relative))
            .unwrap_or_else(|error| panic!("cannot read vendored source {relative}: {error}"));
        tree.update(Sha256::digest(bytes));
    }
    let actual = format!("{:x}", tree.finalize());
    if actual != EXPECTED_VENDOR_TREE_SHA256 {
        panic!(
            "vendored finality source drift: expected {EXPECTED_VENDOR_TREE_SHA256}, got {actual}"
        );
    }

    let checkpoint_fixture = manifest_dir.join("fixtures/finney-grandpa-checkpoint-v1.json");
    println!("cargo:rerun-if-changed={}", checkpoint_fixture.display());
    let fixture_bytes = fs::read(&checkpoint_fixture).unwrap_or_else(|error| {
        panic!(
            "cannot read Finney checkpoint fixture {}: {error}",
            checkpoint_fixture.display()
        )
    });
    let fixture_sha256 = format!("{:x}", Sha256::digest(fixture_bytes));
    if fixture_sha256 != EXPECTED_FINNEY_CHECKPOINT_FIXTURE_SHA256 {
        panic!(
            "Finney checkpoint fixture drift: expected \
             {EXPECTED_FINNEY_CHECKPOINT_FIXTURE_SHA256}, got {fixture_sha256}"
        );
    }
}
