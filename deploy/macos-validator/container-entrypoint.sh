#!/bin/sh

set -eu
umask 077

release_root=/release
private_root=/private
publisher_private_root=/publisher-private
operator_input_root=/operator-input
publisher_input_root=/publisher-input
image_revision_file=/opt/umi-image-revision

fail() {
  printf 'umi-macos-validator: %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Usage: umi-validator-container COMMAND

Commands:
  version          Print the immutable image/runtime identity.
  init-volumes     Initialize persistent Linux volume ownership (root only).
  account-id       Decode UMI_VALIDATOR_HOTKEY to its AccountId32 hex.
  verify           Verify the complete signed inactive release.
  materialize      Materialize this validator's private startup files.
  prime            Prime the next deterministic window before announcement.
  check            Run the full validator startup check without serving a window.
  run              Run the weight-disabled live-shadow validator.
  reconcile        Reconcile one terminal certificate-breach window without scoring.
  audit-check      Verify audit-publication inputs without publishing.
  audit-once       Publish any complete terminal bundle, then exit.
  audit-run        Continuously publish complete terminal bundles.
EOF
}

require_release_revision() {
  [ -f "$release_root/release-manifest.json" ] || fail "signed release manifest is missing"
  [ -f "$image_revision_file" ] || fail "image revision record is missing"
  python - "$release_root/release-manifest.json" "$image_revision_file" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
revision_path = Path(sys.argv[2])
if manifest_path.is_symlink() or revision_path.is_symlink():
    raise SystemExit("release or image revision path is a symlink")
if manifest_path.stat().st_size > 2 * 1024 * 1024:
    raise SystemExit("release manifest exceeds its bootstrap ceiling")
manifest = json.loads(manifest_path.read_bytes())
release_revision = manifest.get("umi_git_revision")
image_revision = revision_path.read_text(encoding="ascii").strip()
if re.fullmatch(r"[0-9a-f]{40}", image_revision) is None:
    raise SystemExit("image revision is malformed")
if release_revision != image_revision:
    raise SystemExit(
        f"image/release revision mismatch: image={image_revision} release={release_revision}"
    )
PY
}

require_authority() {
  : "${UMI_EXPECTED_AUTHORITY_HOTKEY:?set UMI_EXPECTED_AUTHORITY_HOTKEY}"
}

validator_paths() {
  : "${UMI_VALIDATOR_HOTKEY:?set UMI_VALIDATOR_HOTKEY}"
  : "${UMI_VALIDATOR_ACCOUNT_HEX:?set UMI_VALIDATOR_ACCOUNT_HEX}"
  case "$UMI_VALIDATOR_ACCOUNT_HEX" in
    *[!0-9a-f]*|'') fail "UMI_VALIDATOR_ACCOUNT_HEX must be lowercase hexadecimal" ;;
  esac
  [ "${#UMI_VALIDATOR_ACCOUNT_HEX}" -eq 64 ] \
    || fail "UMI_VALIDATOR_ACCOUNT_HEX must encode 32 bytes"
  observed_account=$(python -c \
    'from umi.encoding import account_id32; import os; print(account_id32(os.environ["UMI_VALIDATOR_HOTKEY"]).hex())')
  [ "$observed_account" = "$UMI_VALIDATOR_ACCOUNT_HEX" ] \
    || fail "validator hotkey and AccountId32 disagree"
  validator_config="$private_root/startup-config/operator-templates/${UMI_VALIDATOR_ACCOUNT_HEX}.validator.json"
  operator_config="$private_root/startup-config/operator-templates/${UMI_VALIDATOR_ACCOUNT_HEX}.operator.json"
}

require_hotkey_only_wallet() {
  python - "$operator_config" /wallets <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
wallet_root = Path(sys.argv[2])
if wallet_root.is_symlink() or not wallet_root.is_dir():
    raise SystemExit("runtime wallet root is missing or unsafe")
config = json.loads(config_path.read_bytes())
wallet_path = config.get("wallet_path")
wallet_name = config.get("wallet_name")
hotkey_name = config.get("wallet_hotkey_name")
if wallet_path != "/wallets" or not isinstance(wallet_name, str) or not wallet_name:
    raise SystemExit("operator wallet binding is invalid")
if not isinstance(hotkey_name, str) or not hotkey_name:
    raise SystemExit("operator hotkey binding is invalid")
if Path(wallet_name).name != wallet_name or Path(hotkey_name).name != hotkey_name:
    raise SystemExit("operator wallet names are unsafe")

hotkey_file = wallet_root / wallet_name / "hotkeys" / hotkey_name
wallet_directory = wallet_root / wallet_name
allowed_directories = {
    wallet_root,
    wallet_directory,
    wallet_directory / "hotkeys",
}
allowed_files = {
    hotkey_file,
    wallet_directory / "coldkeypub.txt",
}


def walk_error(error: OSError) -> None:
    raise error


for current, directories, files in os.walk(
    wallet_root,
    topdown=True,
    onerror=walk_error,
    followlinks=False,
):
    current_path = Path(current)
    current_details = current_path.lstat()
    if (
        current_details.st_uid != os.geteuid()
        or current_details.st_gid != os.getegid()
        or stat.S_IMODE(current_details.st_mode) != 0o700
    ):
        raise SystemExit("runtime wallet directory ownership or mode is unsafe")
    for name in directories:
        path = current_path / name
        if path.is_symlink():
            raise SystemExit("runtime wallet tree contains a symlink")
        if path not in allowed_directories:
            raise SystemExit("runtime wallet tree contains an unexpected directory")
    for name in files:
        path = current_path / name
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or path.is_symlink():
            raise SystemExit("runtime wallet tree contains a non-regular file")
        if path not in allowed_files:
            raise SystemExit("runtime wallet tree contains an unexpected file")
        if (
            details.st_uid != os.geteuid()
            or details.st_gid != os.getegid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) not in (0o400, 0o600)
        ):
            raise SystemExit("runtime wallet file ownership, links, or mode are unsafe")

try:
    details = hotkey_file.lstat()
except OSError as error:
    raise SystemExit("configured validator hotkey file is missing") from error
if not stat.S_ISREG(details.st_mode) or hotkey_file.is_symlink():
    raise SystemExit("configured validator hotkey file is unsafe")
PY
}

recovery_paths() {
  validator_paths
  : "${UMI_RECOVERY_WINDOW_ID:?set UMI_RECOVERY_WINDOW_ID}"
  case "$UMI_RECOVERY_WINDOW_ID" in
    *[!0-9a-f]*|'') fail "recovery window ID must be lowercase hexadecimal" ;;
  esac
  [ "${#UMI_RECOVERY_WINDOW_ID}" -eq 64 ] \
    || fail "recovery window ID must encode 32 bytes"
  recovery_root="$operator_input_root/certificate-breach-recovery/$UMI_RECOVERY_WINDOW_ID"
  recovered_objects="$recovery_root/objects"
  reveal_pulse="$recovery_root/reveal-pulse.json"
  incident_bundle="$private_root/state/incident-bundles/$UMI_RECOVERY_WINDOW_ID"
  [ -d "$recovered_objects" ] && [ ! -L "$recovered_objects" ] \
    || fail "recovered object directory is missing or unsafe"
  [ -f "$reveal_pulse" ] && [ ! -L "$reveal_pulse" ] \
    || fail "reveal pulse is missing or unsafe"
}

publication_config() {
  audit_config="$publisher_input_root/audit-publication.json"
  [ -f "$audit_config" ] || fail "audit-publication.json is missing"
}

command_name=${1:-help}
[ "$#" -eq 1 ] || fail "unexpected command arguments"
case "$command_name" in
  help|-h|--help)
    usage
    ;;
  version)
    printf 'umi_git_revision=%s\n' "$(cat "$image_revision_file")"
    printf 'machine=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -s)"
    python --version
    umi-shadow-release-verify --help >/dev/null
    printf 'validator_entrypoints_ready=1\n'
    ;;
  init-volumes)
    [ "$(id -u)" -eq 0 ] || fail "volume initialization requires container root"
    : "${UMI_VOLUME_UID:?set UMI_VOLUME_UID}"
    : "${UMI_VOLUME_GID:?set UMI_VOLUME_GID}"
    case "$UMI_VOLUME_UID" in
      ''|*[!0-9]*) fail "volume UID must be a decimal integer" ;;
    esac
    case "$UMI_VOLUME_GID" in
      ''|*[!0-9]*) fail "volume GID must be a decimal integer" ;;
    esac
    for directory in "$private_root" "$publisher_private_root" /publication; do
      [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "persistent volume root is missing or unsafe: $directory"
      chown 0:0 "$directory"
      chmod 0700 "$directory"
    done
    for directory in /publication/staging /publication/public; do
      mkdir -p "$directory"
      [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "publication volume path is unsafe: $directory"
      chown 0:0 "$directory"
    done
    chmod 0700 /publication/staging
    chmod 0755 /publication/public
    for directory in \
      "$private_root" \
      "$publisher_private_root" \
      /publication/staging \
      /publication/public \
      /publication; do
      chown "$UMI_VOLUME_UID:$UMI_VOLUME_GID" "$directory"
    done
    printf 'persistent_volumes_initialized=1\n'
    ;;
  account-id)
    : "${UMI_VALIDATOR_HOTKEY:?set UMI_VALIDATOR_HOTKEY}"
    exec python -c \
      'from umi.encoding import account_id32; import os; print(account_id32(os.environ["UMI_VALIDATOR_HOTKEY"]).hex())'
    ;;
  verify)
    require_release_revision
    require_authority
    exec umi-shadow-release-verify "$release_root" \
      --expected-authority-hotkey "$UMI_EXPECTED_AUTHORITY_HOTKEY"
    ;;
  materialize)
    require_release_revision
    require_authority
    [ -f "$operator_input_root/local-bindings.json" ] \
      || fail "local-bindings.json is missing"
    [ ! -e "$private_root/startup-config" ] \
      || fail "startup-config already exists; materialization never overwrites"
    exec umi-shadow-release-materialize-operator "$release_root" \
      --expected-authority-hotkey "$UMI_EXPECTED_AUTHORITY_HOTKEY" \
      --local-bindings "$operator_input_root/local-bindings.json" \
      --emit-dir "$private_root/startup-config"
    ;;
  prime)
    require_release_revision
    validator_paths
    exec umi-validator-live --config "$validator_config" --prime-next-window
    ;;
  check)
    require_release_revision
    validator_paths
    require_hotkey_only_wallet
    exec umi-validator-live \
      --config "$validator_config" \
      --operator-config "$operator_config" \
      --check
    ;;
  run)
    require_release_revision
    validator_paths
    require_hotkey_only_wallet
    exec umi-validator-live \
      --config "$validator_config" \
      --operator-config "$operator_config"
    ;;
  reconcile)
    require_release_revision
    recovery_paths
    exec umi-validator-live-reconcile \
      --config "$validator_config" \
      --incident-bundle "$incident_bundle" \
      --recovered-objects "$recovered_objects" \
      --reveal-pulse "$reveal_pulse"
    ;;
  audit-check|audit-once|audit-run)
    require_release_revision
    publication_config
    case "$command_name" in
      audit-check) exec umi-validator-audit-publish --config "$audit_config" --check ;;
      audit-once) exec umi-validator-audit-publish --config "$audit_config" --once ;;
      audit-run) exec umi-validator-audit-publish --config "$audit_config" ;;
    esac
    ;;
  *)
    fail "unknown command: $command_name"
    ;;
esac
