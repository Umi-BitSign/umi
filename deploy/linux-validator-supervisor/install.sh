#!/bin/sh

set -eu
umask 077

service_name=umi-validator-supervisor.service
service_account=umi-validator
supervisor_root=/opt/umi-validator-supervisor
supervisor_executable="$supervisor_root/.venv/bin/umi-validator-supervisor"
service_destination="/etc/systemd/system/$service_name"
runtime_service_destination="/run/systemd/system/$service_name"
runtime_service_dropin_directory="/run/systemd/system/$service_name.d"
runtime_service_dropin_destination="$runtime_service_dropin_directory/10-runtime-smoke.conf"
config_destination=/etc/umi/validator-supervisor.json
runtime_wallet_root=/var/lib/umi-validator-runtime-wallets
runtime_smoke_mount_root=/var/lib/umi-validator-runtime-smoke
runtime_smoke_readonly_mount="$runtime_smoke_mount_root/readonly"
runtime_smoke_readwrite_mount="$runtime_smoke_mount_root/readwrite"
archive_root=/var/lib/umi-validator-retired-units
origin=https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev

fail() {
  printf 'umi-validator-supervisor-install: %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Usage: sudo ./deploy/linux-validator-supervisor/install.sh \
  --wallet-name NAME --hotkey-name NAME --wallet-path /ABSOLUTE/WALLET/ROOT \
  [--legacy-unit EXACT_SYSTEM_SERVICE.service]

The installer copies only the named plaintext hotkey into an isolated runtime
wallet. It never copies or reads a coldkey. If --legacy-unit is supplied, every
download, signature check, host check, and worker preflight completes before
that unit is stopped and disabled.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_real_directory_target() {
  target=$1
  [ ! -L "$target" ] || fail "managed directory target is a symlink: $target"
  if [ -e "$target" ]; then
    [ -d "$target" ] || fail "managed directory target is not a directory: $target"
  fi
}

require_empty_unit_control_group() {
  control_group=$1
  [ -n "$control_group" ] || return 0
  case "$control_group" in
    /) fail "legacy unit unexpectedly owns the root control group" ;;
    /*) ;;
    *) fail "legacy unit control group is not absolute" ;;
  esac
  control_group_path="/sys/fs/cgroup$control_group"
  [ ! -e "$control_group_path" ] && [ ! -L "$control_group_path" ] && return 0
  [ -d "$control_group_path" ] && [ ! -L "$control_group_path" ] \
    || fail "legacy unit control group is not a real directory"
  empty_attempt=0
  while [ "$empty_attempt" -lt 10 ]; do
    control_group_pids=$(find "$control_group_path" -type f -name cgroup.procs \
      -exec sh -c 'for item do sed -n "1p" "$item"; done' sh {} + 2>/dev/null) \
      || fail "could not inspect every legacy unit control-group process list"
    [ -z "$control_group_pids" ] && return 0
    empty_attempt=$((empty_attempt + 1))
    sleep 1
  done
  fail "legacy unit control group still contains a process after retirement"
}

range_is_free() {
  subordinate_file=$1
  candidate_start=$2
  awk -F: -v candidate_start="$candidate_start" -v candidate_count=65536 '
    /^[[:space:]]*($|#)/ { next }
    NF != 3 || $1 == "" || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ { exit 2 }
    {
      start = $2 + 0
      count = $3 + 0
      end = start + count - 1
      candidate_end = candidate_start + candidate_count - 1
      if (count < 1 || start < 1 || end < start || end > 4294967295) { exit 2 }
      if (start <= candidate_end && candidate_start <= end) { exit 1 }
    }
    END { if (candidate_start + candidate_count - 1 > 4294967295) exit 2 }
  ' "$subordinate_file"
}

add_subordinate_range_if_missing() {
  subordinate_file=$1
  option=$2
  if awk -F: -v account="$service_account" -v uid="$service_uid" '
    $1 == account || $1 == uid { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$subordinate_file"
  then
    return 0
  fi
  candidate_start=2000027648
  candidate_attempt=0
  while [ "$candidate_attempt" -lt 10000 ]; do
    if range_is_free "$subordinate_file" "$candidate_start"; then
      candidate_end=$((candidate_start + 65535))
      usermod "$option" "$candidate_start-$candidate_end" "$service_account"
      return 0
    fi
    candidate_start=$((candidate_start + 65536))
    candidate_attempt=$((candidate_attempt + 1))
  done
  fail "no unallocated 65536-ID range was found for $service_account in $subordinate_file"
}

require_private_subordinate_range() {
  subordinate_file=$1
  checker=$2
  [ -f "$subordinate_file" ] && [ ! -L "$subordinate_file" ] \
    || fail "subordinate-ID file is missing or unsafe: $subordinate_file"
  [ "$(stat -c '%u' "$subordinate_file")" -eq 0 ] \
    || fail "subordinate-ID file must be owned by root: $subordinate_file"
  subordinate_mode=$(stat -c '%a' "$subordinate_file")
  [ "$((0$subordinate_mode & 0022))" -eq 0 ] \
    || fail "subordinate-ID file is group- or world-writable: $subordinate_file"
  [ "$(stat -c '%h' "$subordinate_file")" -eq 1 ] \
    || fail "subordinate-ID file must not be hard-linked: $subordinate_file"
  awk -F: -v account="$service_account" -v uid="$service_uid" -f "$checker" \
    "$subordinate_file" \
    || fail "$subordinate_file does not contain one private 65536-ID range for $service_account"
}

require_immutable_supervisor_tree() {
  unsafe_path=$(find "$supervisor_root" -xdev ! -type l \
    \( ! -user root -o -perm /0022 -o -perm /07000 \) -print -quit) \
    || fail "could not inspect the installed supervisor tree"
  [ -z "$unsafe_path" ] \
    || fail "installed supervisor tree contains a non-root-owned or writable path"
  unsafe_link=$(find "$supervisor_root" -xdev -type l ! -user root -print -quit) \
    || fail "could not inspect installed supervisor symlinks"
  [ -z "$unsafe_link" ] || fail "installed supervisor tree contains an unowned symlink"
  find "$supervisor_root" -xdev -type l -exec sh -c '
    root=$1
    shift
    for link do
      target=$(readlink -f -- "$link") || exit 1
      case "$target" in "$root"/*) ;; *) exit 1 ;; esac
    done
  ' sh "$supervisor_root" {} + \
    || fail "installed supervisor tree has a broken or escaping symlink"
}

cleanup_runtime_smoke_unit() {
  [ "${runtime_smoke_staged:-false}" = true ] || return 0
  systemctl stop "$service_name" >/dev/null 2>&1 || :
  systemctl reset-failed "$service_name" >/dev/null 2>&1 || :
  rm -f -- "$runtime_service_dropin_destination" || :
  rmdir -- "$runtime_service_dropin_directory" >/dev/null 2>&1 || :
  rm -f -- "$runtime_service_destination" || :
  systemctl daemon-reload >/dev/null 2>&1 || :
  runtime_smoke_staged=false
}

remove_runtime_smoke_unit() {
  systemctl stop "$service_name" \
    || fail "could not stop the production-unit runtime smoke"
  # Reset while the transient fragment is still loaded. On a first install,
  # systemd may forget the unit as soon as its final fragment is removed.
  systemctl reset-failed "$service_name" \
    || fail "could not reset the production-unit runtime smoke state"
  rm -f -- "$runtime_service_dropin_destination"
  rmdir -- "$runtime_service_dropin_directory" \
    || fail "could not remove the production-unit runtime smoke drop-in directory"
  rm -f -- "$runtime_service_destination"
  systemctl daemon-reload \
    || fail "could not unload the production-unit runtime smoke"
  [ "$(systemctl show "$service_name" --property=LoadState --value)" = not-found ] \
    || fail "production-unit runtime smoke remained loaded"
  runtime_smoke_staged=false
}

supervisor() {
  (
    CDPATH= cd -- /
    runuser -u "$service_account" -- env -i \
      CONTAINERS_CONF_OVERRIDE=/opt/umi-validator-supervisor/deploy/linux-validator-supervisor/containers.conf \
      HOME=/var/lib/umi-validator-supervisor/home \
      XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
      XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
      XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
      LOGNAME="$service_account" \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONUTF8=1 \
      USER="$service_account" "$supervisor_executable" "$@"
  )
}

podman_as_service() {
  (
    CDPATH= cd -- /
    runuser -u "$service_account" -- env -i \
      CONTAINERS_CONF_OVERRIDE=/opt/umi-validator-supervisor/deploy/linux-validator-supervisor/containers.conf \
      HOME=/var/lib/umi-validator-supervisor/home \
      XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
      XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
      XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
      LOGNAME="$service_account" \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      USER="$service_account" \
      /usr/bin/timeout --signal=TERM --kill-after=5s 30s \
      /usr/bin/podman "$@"
  )
}

[ "$(id -u)" -eq 0 ] || fail "run this installer with sudo"

wallet_name=
hotkey_name=
wallet_path=
legacy_unit=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --wallet-name)
      [ "$#" -ge 2 ] || fail "--wallet-name requires a value"
      wallet_name=$2
      shift 2
      ;;
    --hotkey-name)
      [ "$#" -ge 2 ] || fail "--hotkey-name requires a value"
      hotkey_name=$2
      shift 2
      ;;
    --wallet-path)
      [ "$#" -ge 2 ] || fail "--wallet-path requires an absolute path"
      wallet_path=$2
      shift 2
      ;;
    --legacy-unit)
      [ "$#" -ge 2 ] || fail "--legacy-unit requires one service name"
      legacy_unit=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ -n "$wallet_name" ] || fail "--wallet-name is required"
[ -n "$hotkey_name" ] || fail "--hotkey-name is required"
[ -n "$wallet_path" ] || fail "--wallet-path is required"
case "$wallet_name" in ''|*/*|*[!A-Za-z0-9_.-]*) fail "wallet name is invalid" ;; esac
case "$hotkey_name" in ''|*/*|*[!A-Za-z0-9_.-]*) fail "hotkey name is invalid" ;; esac
case "$wallet_path" in /*) ;; *) fail "--wallet-path must be absolute" ;; esac
if [ -n "$legacy_unit" ]; then
  case "$legacy_unit" in *.service) ;; *) fail "legacy unit must include .service" ;; esac
  case "$legacy_unit" in ''|*/*|*[!A-Za-z0-9_.@-]*) fail "legacy unit name is invalid" ;; esac
  [ "$legacy_unit" != "$service_name" ] || fail "refusing to retire the UMI supervisor"
fi

package_commands='awk chmod chown crun curl cut find getent git groupadd install mkdir mktemp mv newgidmap newuidmap podman readlink rmdir rm runuser sed sha256sum slirp4netns stat systemctl systemd-analyze tar timeout useradd usermod'
missing_package_command=false
for command_name in $package_commands; do
  command -v "$command_name" >/dev/null 2>&1 || missing_package_command=true
done
if [ "$missing_package_command" = true ]; then
  [ -r /etc/os-release ] \
    || fail "install Podman, slirp4netns, uidmap, curl, Git, and systemd first"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*) ;;
    *) fail "install Podman, slirp4netns, uidmap, curl, Git, and systemd first" ;;
  esac
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    --no-upgrade --no-remove \
    ca-certificates crun curl git podman slirp4netns uidmap util-linux \
    coreutils findutils gawk tar
fi
for command_name in $package_commands; do require_command "$command_name"; done

podman_version=$(podman --version | awk '{print $3}') \
  || fail "could not read the Podman version"
podman_major=${podman_version%%.*}
podman_remainder=${podman_version#*.}
podman_minor=${podman_remainder%%.*}
case "$podman_major:$podman_minor" in
  ''|:*|*:|*[!0-9:]*) fail "could not parse the Podman version: $podman_version" ;;
esac
if [ "$podman_major" -lt 4 ] \
  || { [ "$podman_major" -eq 4 ] && [ "$podman_minor" -lt 3 ]; }
then
  fail "Podman 4.3.0 or later is required; found $podman_version"
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
source_root=$(git -c safe.directory='*' -C "$script_directory" rev-parse --show-toplevel \
  2>/dev/null) || fail "installer must run from a Git checkout"
source_root=$(readlink -f -- "$source_root") || fail "could not resolve the source checkout"
[ "$script_directory" = "$source_root/deploy/linux-validator-supervisor" ] \
  || fail "installer path does not match the source checkout"
revision=$(git -c safe.directory="$source_root" -C "$source_root" \
  rev-parse --verify HEAD^{commit}) || fail "could not resolve the source revision"
[ "${#revision}" -eq 40 ] || fail "source revision is not a full Git commit"
case "$revision" in *[!0-9a-f]*) fail "source revision is not lowercase hexadecimal" ;; esac
[ -z "$(git -c safe.directory="$source_root" -C "$source_root" \
  status --porcelain=v1 --untracked-files=all)" ] \
  || fail "source checkout must be clean before installation"

case "$(uname -m)" in
  x86_64|amd64)
    target_platform=linux/amd64
    platform_suffix=linux-amd64
    channel_id=a3ca19a108fe7d1a8e53a2db76f480ebe237b7942595f23135d6e11889ed40c0
    uv_target=x86_64-unknown-linux-musl
    uv_archive_sha256=aa4b1f8770910f7c7c543c7acc980e4270e52e70750c996acef813ea1c7c2912
    uv_binary_sha256=308d3841102bffca4acfe799e726db08846ee35f7408762a02349c42d1ba0a09
    ;;
  aarch64|arm64)
    target_platform=linux/arm64
    platform_suffix=linux-arm64
    channel_id=85ea6ef2c7e4f24d9d0eefa367425119b509e8604ce1675443efcbacc7bb4461
    uv_target=aarch64-unknown-linux-musl
    uv_archive_sha256=7eb9bf48516448c9db6a9e436d8e747ac9c8a9cac74717160a29918249b080a6
    uv_binary_sha256=8353b259b2486ab011aae51f8815f88b41648e2ee8fe68494a8379b9f59377c8
    ;;
  *) fail "supported hosts are Linux x86_64 and Linux arm64" ;;
esac

wallet_path=$(readlink -f -- "$wallet_path") || fail "wallet path does not exist"
[ -d "$wallet_path" ] && [ ! -L "$wallet_path" ] \
  || fail "wallet path must resolve to a real directory"
wallet_directory="$wallet_path/$wallet_name"
wallet_hotkeys="$wallet_directory/hotkeys"
hotkey_source="$wallet_hotkeys/$hotkey_name"
[ -d "$wallet_directory" ] && [ ! -L "$wallet_directory" ] \
  || fail "wallet directory is missing or is a symlink"
[ -d "$wallet_hotkeys" ] && [ ! -L "$wallet_hotkeys" ] \
  || fail "wallet hotkeys directory is missing or is a symlink"
[ -f "$hotkey_source" ] && [ ! -L "$hotkey_source" ] \
  || fail "named hotkey file is missing or is a symlink"
[ "$(stat -c '%h' "$hotkey_source")" -eq 1 ] \
  || fail "named hotkey file must not be hard-linked"
hotkey_size=$(stat -c '%s' "$hotkey_source")
[ "$hotkey_size" -gt 0 ] && [ "$hotkey_size" -le 65536 ] \
  || fail "named hotkey file has an invalid size"

[ ! -e "$supervisor_root" ] && [ ! -L "$supervisor_root" ] \
  || fail "an installed supervisor tree already exists"
[ ! -e "$config_destination" ] && [ ! -L "$config_destination" ] \
  || fail "an installed supervisor config already exists"
[ ! -e "$service_destination" ] && [ ! -L "$service_destination" ] \
  || fail "an installed supervisor service already exists"
[ ! -e "$runtime_service_destination" ] && [ ! -L "$runtime_service_destination" ] \
  || fail "the supervisor runtime service path already exists"
[ ! -e "$runtime_service_dropin_directory" ] \
  && [ ! -L "$runtime_service_dropin_directory" ] \
  || fail "the supervisor runtime service drop-in path already exists"
[ ! -e "$runtime_smoke_mount_root" ] && [ ! -L "$runtime_smoke_mount_root" ] \
  || fail "the Podman runtime-smoke mount root already exists"
service_load_state=$(systemctl show "$service_name" --property=LoadState --value) \
  || fail "could not inspect the supervisor unit name"
[ "$service_load_state" = not-found ] \
  || fail "the supervisor unit name is already loaded"

legacy_control_group=
legacy_fragment=
archive_path=
if [ -n "$legacy_unit" ]; then
  [ "$(systemctl show "$legacy_unit" --property=LoadState --value)" = loaded ] \
    || fail "legacy unit is not one loaded system service"
  legacy_control_group=$(systemctl show "$legacy_unit" --property=ControlGroup --value)
  case "$legacy_control_group" in ''|/*) ;; *) fail "legacy control group is invalid" ;; esac
  legacy_fragment=$(systemctl show "$legacy_unit" --property=FragmentPath --value)
  case "$legacy_fragment" in
    "/etc/systemd/system/$legacy_unit")
      archive_path="$archive_root/$legacy_unit.$revision"
      [ ! -e "$archive_path" ] && [ ! -L "$archive_path" ] \
        || fail "legacy unit archive target already exists"
      ;;
    /usr/lib/systemd/system/*|/lib/systemd/system/*) ;;
    *) fail "legacy unit has an unsupported fragment path" ;;
  esac
fi

temporary_root=$(mktemp -d /tmp/umi-validator-supervisor-install.XXXXXXXX) \
  || fail "could not allocate a temporary directory"
supervisor_created=false
runtime_wallet_created=false
runtime_smoke_mount_root_created=false
runtime_smoke_staged=false
retain_installation=false
cleanup() {
  cleanup_runtime_smoke_unit
  rm -rf -- "$temporary_root"
  if [ -n "${config_build:-}" ]; then rm -f -- "$config_build"; fi
  if [ -n "${config_stage:-}" ]; then rm -f -- "$config_stage"; fi
  if [ "$retain_installation" = false ]; then
    if [ "$runtime_wallet_created" = true ]; then
      rm -rf -- "$runtime_wallet_root/$wallet_name"
    fi
    if [ "$supervisor_created" = true ]; then
      rm -rf -- "$supervisor_root"
    fi
    if [ "$runtime_smoke_mount_root_created" = true ]; then
      rm -rf -- "$runtime_smoke_mount_root"
    fi
  fi
}
trap cleanup EXIT HUP INT TERM

uv_archive="$temporary_root/uv.tar.gz"
uv_extract="$temporary_root/uv-extract"
mkdir -m 0700 "$uv_extract"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --max-filesize 67108864 \
  --output "$uv_archive" \
  "https://github.com/astral-sh/uv/releases/download/0.12.9/uv-$uv_target.tar.gz"
printf '%s  %s\n' "$uv_archive_sha256" "$uv_archive" | sha256sum --check --status \
  || fail "downloaded uv archive failed its pinned SHA-256 check"
tar --extract --gzip --file "$uv_archive" --directory "$uv_extract" --strip-components=1
uv_source="$uv_extract/uv"
[ -f "$uv_source" ] && [ ! -L "$uv_source" ] \
  || fail "uv archive did not contain the expected binary"
printf '%s  %s\n' "$uv_binary_sha256" "$uv_source" | sha256sum --check --status \
  || fail "extracted uv binary failed its pinned SHA-256 check"
[ "$("$uv_source" --version | awk '{print $1 " " $2}')" = 'uv 0.12.9' ] \
  || fail "downloaded uv binary has the wrong version"

supervisor_created=true
git -c safe.directory="$source_root" clone --no-local --no-hardlinks --no-checkout \
  "$source_root" "$supervisor_root"
git -c safe.directory="$supervisor_root" -C "$supervisor_root" checkout --detach "$revision"
[ "$(git -c safe.directory="$supervisor_root" -C "$supervisor_root" rev-parse HEAD)" \
  = "$revision" ] || fail "installed checkout has the wrong revision"
[ -z "$(git -c safe.directory="$supervisor_root" -C "$supervisor_root" \
  status --porcelain=v1 --untracked-files=all)" ] \
  || fail "installed checkout is not clean"
install -o root -g root -m 0755 "$uv_source" "$supervisor_root/.uv-bootstrap-0.12.9"
env UV_PYTHON_INSTALL_DIR="$supervisor_root/.uv-python" \
  "$supervisor_root/.uv-bootstrap-0.12.9" python install 3.12.14
env UV_PYTHON_INSTALL_DIR="$supervisor_root/.uv-python" \
  UV_PROJECT_ENVIRONMENT="$supervisor_root/.venv" \
  "$supervisor_root/.uv-bootstrap-0.12.9" sync --project "$supervisor_root" \
    --locked --no-dev --no-editable --python 3.12.14
[ "$("$supervisor_root/.venv/bin/python" --version)" = 'Python 3.12.14' ] \
  || fail "the locked Python runtime was not installed"
[ -x "$supervisor_executable" ] || fail "the supervisor executable was not installed"

installed_deploy="$supervisor_root/deploy/linux-validator-supervisor"
service_source="$installed_deploy/umi-validator-supervisor.service"
subordinate_range_checker="$installed_deploy/check-subordinate-ranges.awk"
containers_conf_source="$installed_deploy/containers.conf"
podman_smoke_source="$installed_deploy/podman-runtime-smoke.sh"
runtime_smoke_dropin_source="$installed_deploy/runtime-smoke.conf"
[ -f "$service_source" ] && [ ! -L "$service_source" ] \
  || fail "the checked-in service unit is missing or unsafe"
[ -f "$subordinate_range_checker" ] && [ ! -L "$subordinate_range_checker" ] \
  || fail "the subordinate-ID checker is missing or unsafe"
[ -f "$containers_conf_source" ] && [ ! -L "$containers_conf_source" ] \
  || fail "the checked-in containers.conf is missing or unsafe"
[ -f "$podman_smoke_source" ] && [ ! -L "$podman_smoke_source" ] \
  || fail "the checked-in Podman runtime smoke is missing or unsafe"
[ -f "$runtime_smoke_dropin_source" ] && [ ! -L "$runtime_smoke_dropin_source" ] \
  || fail "the checked-in runtime-smoke drop-in is missing or unsafe"

if ! getent group "$service_account" >/dev/null 2>&1; then groupadd --system "$service_account"; fi
if ! id "$service_account" >/dev/null 2>&1; then
  useradd --system --gid "$service_account" --no-create-home \
    --home-dir /var/lib/umi-validator-supervisor --shell /usr/sbin/nologin \
    "$service_account"
fi
[ "$(id -gn "$service_account")" = "$service_account" ] \
  || fail "service account has an unexpected primary group"
service_uid=$(id -u "$service_account")
[ "$service_uid" -gt 0 ] || fail "service account must not be UID 0"
[ "$(id -g "$service_account")" -gt 0 ] || fail "service group must not be GID 0"
[ "$(getent passwd "$service_account" | cut -d: -f6)" = /var/lib/umi-validator-supervisor ] \
  || fail "service account has an unexpected home directory"
case "$(getent passwd "$service_account" | cut -d: -f7)" in
  /usr/sbin/nologin|/sbin/nologin) ;;
  *) fail "service account must use a nologin shell" ;;
esac

add_subordinate_range_if_missing /etc/subuid --add-subuids
add_subordinate_range_if_missing /etc/subgid --add-subgids
require_private_subordinate_range /etc/subuid "$subordinate_range_checker"
require_private_subordinate_range /etc/subgid "$subordinate_range_checker"
[ "$(id -nG "$service_account")" = "$service_account" ] \
  || fail "service account must not belong to supplementary groups"

for managed_directory in \
  /etc/umi "$runtime_wallet_root" /var/lib/umi-validator-operator-inputs \
  /var/lib/umi-validator-supervisor \
  /var/lib/umi-validator-supervisor/container-config \
  /var/lib/umi-validator-supervisor/container-data \
  /var/lib/umi-validator-supervisor/home \
  /var/lib/umi-validator-supervisor/state \
  /var/lib/umi-validator-supervisor/releases \
  /var/lib/umi-validator-worker-state /run/umi-validator-supervisor
do
  require_real_directory_target "$managed_directory"
done
install -d -o root -g root -m 0755 /etc/umi
install -d -o root -g "$service_account" -m 0750 "$runtime_wallet_root"
install -d -o "$service_account" -g "$service_account" -m 0700 \
  /var/lib/umi-validator-operator-inputs /var/lib/umi-validator-supervisor \
  /var/lib/umi-validator-supervisor/container-config \
  /var/lib/umi-validator-supervisor/container-data \
  /var/lib/umi-validator-supervisor/home \
  /var/lib/umi-validator-supervisor/state \
  /var/lib/umi-validator-supervisor/releases \
  /var/lib/umi-validator-worker-state /run/umi-validator-supervisor

runtime_smoke_mount_root_created=true
install -d -o root -g root -m 0755 "$runtime_smoke_mount_root"
install -d -o root -g root -m 0555 "$runtime_smoke_readonly_mount"
install -d -o "$service_account" -g "$service_account" -m 0700 \
  "$runtime_smoke_readwrite_mount"
[ "$(stat -c '%u:%g:%a' "$runtime_smoke_mount_root")" = '0:0:755' ] \
  || fail "Podman runtime-smoke mount root has unsafe ownership or mode"
[ "$(stat -c '%u:%g:%a' "$runtime_smoke_readonly_mount")" = '0:0:555' ] \
  || fail "Podman read-only runtime-smoke mount has unsafe ownership or mode"
[ "$(stat -c '%u:%g:%a' "$runtime_smoke_readwrite_mount")" \
  = "$service_uid:$(id -g "$service_account"):700" ] \
  || fail "Podman read-write runtime-smoke mount has unsafe ownership or mode"
[ -z "$(find "$runtime_smoke_mount_root" -mindepth 2 -print -quit)" ] \
  || fail "Podman runtime-smoke mounts must start empty"

runtime_wallet="$runtime_wallet_root/$wallet_name"
runtime_hotkeys="$runtime_wallet/hotkeys"
[ ! -e "$runtime_wallet" ] && [ ! -L "$runtime_wallet" ] \
  || fail "isolated runtime wallet target already exists"
runtime_wallet_created=true
install -d -o "$service_account" -g "$service_account" -m 0700 \
  "$runtime_wallet" "$runtime_hotkeys"
install -o "$service_account" -g "$service_account" -m 0400 \
  "$hotkey_source" "$runtime_hotkeys/$hotkey_name"

artifacts_directory="$supervisor_root/artifacts"
install -d -o root -g root -m 0755 "$artifacts_directory"
host_manifest="$temporary_root/host-artifacts.json"
host_manifest_url="$origin/validator-supervisor/channels/$channel_id/$platform_suffix/host-artifacts.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --max-filesize 1048576 \
  --output "$host_manifest" "$host_manifest_url"
"$supervisor_executable" install-common-host-artifacts \
  --manifest "$host_manifest" --target-platform "$target_platform" \
  --expected-revision "$revision" --destination "$artifacts_directory"
finality_sha256=$(sha256sum "$artifacts_directory/umi-grandpa-finality-observer" \
  | cut -d' ' -f1)
[ "$("$artifacts_directory/uv" --version | awk '{print $1 " " $2}')" = 'uv 0.12.9' ] \
  || fail "the signed host uv binary has the wrong version"

chown -R root:root "$supervisor_root"
find "$supervisor_root" -xdev -type d -exec chmod 0755 {} +
find "$supervisor_root" -xdev -type f -perm /0111 -exec chmod 0755 {} +
find "$supervisor_root" -xdev -type f ! -perm /0111 -exec chmod 0644 {} +
chmod 0444 "$containers_conf_source"
chmod 0555 "$podman_smoke_source"
chmod 0444 "$runtime_smoke_dropin_source"
chmod 0555 "$artifacts_directory/uv" "$artifacts_directory/umi-grandpa-finality-observer"
chmod 0444 "$artifacts_directory/raw_spec_finney.json"
require_immutable_supervisor_tree

config_build=/var/lib/umi-validator-supervisor/.validator-supervisor.json.building
config_stage=/etc/umi/.validator-supervisor.json.installing
[ ! -e "$config_build" ] && [ ! -L "$config_build" ] \
  || fail "temporary config output already exists"
[ ! -e "$config_stage" ] && [ ! -L "$config_stage" ] \
  || fail "temporary config stage already exists"
supervisor build-common-config --wallet-name "$wallet_name" \
  --wallet-hotkey "$hotkey_name" --target-platform "$target_platform" \
  --finality-verifier-sha256 "$finality_sha256" --output "$config_build"
install -o root -g "$service_account" -m 0640 "$config_build" "$config_stage"
rm -f -- "$config_build"

systemd-analyze verify "$service_source"
[ "$(podman_as_service info --format '{{.Host.Security.Rootless}}')" = true ] \
  || fail "Podman did not report a rootless service context"
[ "$(podman_as_service info --format '{{.Host.CgroupsVersion}}')" = v2 ] \
  || fail "rootless Podman requires cgroup v2"
[ "$(podman_as_service info --format '{{.Host.CgroupManager}}')" = cgroupfs ] \
  || fail "rootless Podman did not use the signed cgroupfs configuration"
[ "$(podman_as_service info --format '{{.Host.OCIRuntime.Name}}')" = crun ] \
  || fail "rootless Podman must use crun"
case "$(podman_as_service info --format '{{.Store.GraphRoot}}')" in
  /var/lib/umi-validator-supervisor/container-data/*) ;;
  *) fail "rootless Podman graph root escaped the supervisor state tree" ;;
esac
case "$(podman_as_service info --format '{{.Store.RunRoot}}')" in
  /run/umi-validator-supervisor/*) ;;
  *) fail "rootless Podman run root escaped the supervisor runtime tree" ;;
esac
podman_as_service unshare /usr/bin/true \
  || fail "rootless Podman user-namespace preflight failed"
supervisor check-config --config "$config_stage" --profile linux-systemd-v1

# This stages and verifies the current signed worker without starting it or
# writing supervisor state. The signed sequence-1 hold is checked as history.
# No legacy process is stopped until this command succeeds.
supervisor preflight-common-switch --config "$config_stage"

# Rehearse the exact production unit name and sandbox before any legacy writer
# is touched. The checked-in drop-in keeps only ExecStartPre live and replaces
# the signing supervisor process with /usr/bin/true for this one-shot gate.
runtime_smoke_staged=true
install -o root -g root -m 0644 "$service_source" "$runtime_service_destination"
install -d -o root -g root -m 0755 "$runtime_service_dropin_directory"
install -o root -g root -m 0644 \
  "$runtime_smoke_dropin_source" "$runtime_service_dropin_destination"
[ "$(sha256sum "$service_source" | cut -d' ' -f1)" \
  = "$(sha256sum "$runtime_service_destination" | cut -d' ' -f1)" ] \
  || fail "staged runtime-smoke service drifted from the production unit"
[ "$(sha256sum "$runtime_smoke_dropin_source" | cut -d' ' -f1)" \
  = "$(sha256sum "$runtime_service_dropin_destination" | cut -d' ' -f1)" ] \
  || fail "staged runtime-smoke drop-in drifted from its checked-in source"
systemctl daemon-reload
[ "$(systemctl show "$service_name" --property=FragmentPath --value)" \
  = "$runtime_service_destination" ] \
  || fail "runtime smoke did not load the production service fragment"
[ "$(systemctl show "$service_name" --property=DropInPaths --value)" \
  = "$runtime_service_dropin_destination" ] \
  || fail "runtime smoke loaded an unexpected drop-in set"
[ "$(systemctl show "$service_name" --property=Type --value)" = oneshot ] \
  || fail "runtime-smoke service type override was not applied"
[ "$(systemctl show "$service_name" --property=Restart --value)" = no ] \
  || fail "runtime-smoke restart override was not applied"
[ "$(systemctl show "$service_name" --property=RuntimeDirectoryPreserve --value)" = yes ] \
  || fail "runtime-smoke rootless-Podman namespace state would not be preserved"
case "$(systemctl show "$service_name" --property=ExecStart --value)" in
  *'path=/usr/bin/true'*'argv[]=/usr/bin/true'*) ;;
  *) fail "runtime-smoke inert ExecStart override was not applied" ;;
esac
systemctl start "$service_name" \
  || fail "production-unit Podman runtime smoke failed"
[ "$(systemctl show "$service_name" --property=Result --value)" = success ] \
  || fail "production-unit Podman runtime smoke did not succeed"
[ "$(systemctl show "$service_name" --property=ExecMainStatus --value)" = 0 ] \
  || fail "production-unit inert ExecStart did not exit successfully"
remove_runtime_smoke_unit

if [ -n "$legacy_unit" ]; then
  retain_installation=true
  systemctl disable --now "$legacy_unit"
  systemctl kill --kill-whom=all --signal=SIGKILL "$legacy_unit" >/dev/null 2>&1 || :
  if systemctl is-active --quiet "$legacy_unit"; then
    fail "legacy unit remained active after stop"
  fi
  [ "$(systemctl show "$legacy_unit" --property=MainPID --value)" = 0 ] \
    || fail "legacy unit still has a main process after stop"
  require_empty_unit_control_group "$legacy_control_group"
  if [ "$legacy_fragment" = "/etc/systemd/system/$legacy_unit" ]; then
    install -d -o root -g root -m 0700 "$archive_root"
    mv -- "$legacy_fragment" "$archive_path"
    chmod 0600 "$archive_path"
    systemctl daemon-reload
  fi
  systemctl mask "$legacy_unit"
  [ "$(systemctl is-enabled "$legacy_unit" 2>/dev/null || :)" = masked ] \
    || fail "legacy unit is not masked"
fi

retain_installation=true
mv -- "$config_stage" "$config_destination"
install -o root -g root -m 0644 "$service_source" "$service_destination"
systemctl daemon-reload
systemctl enable --now "$service_name"

readiness_attempt=0
supervisor_ready=false
while [ "$readiness_attempt" -lt 180 ]; do
  if systemctl is-active --quiet "$service_name"; then
    status_output=$(supervisor status --config "$config_destination" 2>/dev/null || :)
    case "$status_output" in
      *'"daemon_running":true'*) supervisor_ready=true; break ;;
    esac
  fi
  readiness_attempt=$((readiness_attempt + 1))
  sleep 1
done
[ "$supervisor_ready" = true ] || fail "UMI supervisor did not establish its process lock"

trap - EXIT HUP INT TERM
cleanup
printf 'status=installed\n'
printf 'revision=%s\n' "$revision"
printf 'target_platform=%s\n' "$target_platform"
printf 'channel_id=%s\n' "$channel_id"
if [ -n "$legacy_unit" ]; then
  printf 'legacy_unit=%s\n' "$legacy_unit"
  printf 'legacy_unit_state=disabled_inactive\n'
else
  printf 'legacy_action=none\n'
fi
