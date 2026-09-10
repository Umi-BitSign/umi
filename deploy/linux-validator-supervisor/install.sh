#!/bin/sh

set -eu
umask 077

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
service_source="$script_directory/umi-validator-supervisor.service"
subordinate_range_checker="$script_directory/check-subordinate-ranges.awk"
service_name=umi-validator-supervisor.service
service_destination="/etc/systemd/system/$service_name"
config_destination=/etc/umi/validator-supervisor.json
service_account=umi-validator
archive_root=/var/lib/umi-validator-retired-units
supervisor_root=/opt/umi-validator-supervisor
supervisor_executable=/opt/umi-validator-supervisor/.venv/bin/umi-validator-supervisor
container_runtime=/usr/bin/podman
slirp4netns_binary=/usr/bin/slirp4netns
bootstrap_upload_root=/var/lib/umi-validator-bootstrap-upload
bootstrap_upload_credential="$bootstrap_upload_root/bootstrap-result-upload.key"

fail() {
  printf 'umi-validator-supervisor-install: %s\n' "$*" >&2
  exit 2
}

require_real_directory_target() {
  target=$1
  [ ! -L "$target" ] || fail "managed directory target is a symlink: $target"
  if [ -e "$target" ]; then
    [ -d "$target" ] || fail "managed directory target is not a directory: $target"
  fi
}

require_private_subordinate_range() {
  subordinate_file=$1
  [ -f "$subordinate_file" ] || fail "subordinate-ID file is missing: $subordinate_file"
  [ ! -L "$subordinate_file" ] \
    || fail "subordinate-ID file must not be a symlink: $subordinate_file"
  [ "$(stat -c '%u' "$subordinate_file")" -eq 0 ] \
    || fail "subordinate-ID file must be owned by root: $subordinate_file"
  subordinate_mode=$(stat -c '%a' "$subordinate_file")
  [ "$((0$subordinate_mode & 0022))" -eq 0 ] \
    || fail "subordinate-ID file is group- or world-writable: $subordinate_file"
  [ "$(stat -c '%h' "$subordinate_file")" -eq 1 ] \
    || fail "subordinate-ID file must not be hard-linked: $subordinate_file"
  awk -F: -v account="$service_account" -v uid="$service_uid" \
    -f "$subordinate_range_checker" "$subordinate_file" \
    || fail "$subordinate_file needs a valid, unshared 65536-ID range for $service_account"
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
    control_group_pids=$(
      find "$control_group_path" -type f -name cgroup.procs -exec cat -- {} + 2>/dev/null
    ) || fail "could not inspect every legacy unit control-group process list"
    [ -z "$control_group_pids" ] && return 0
    empty_attempt=$((empty_attempt + 1))
    sleep 1
  done
  fail "legacy unit control group still contains a process after retirement"
}

require_immutable_supervisor_tree() {
  unsafe_supervisor_path=$(
    find "$supervisor_root" -xdev ! -type l \
      \( ! -user root -o -perm /0022 -o -perm /07000 \) -print -quit
  ) || fail "could not inspect the pinned supervisor tree"
  [ -z "$unsafe_supervisor_path" ] \
    || fail "pinned supervisor tree contains a non-root-owned or writable path"
  unsafe_supervisor_link=$(
    find "$supervisor_root" -xdev -type l ! -user root -print -quit
  ) || fail "could not inspect ownership of supervisor symlinks"
  [ -z "$unsafe_supervisor_link" ] \
    || fail "pinned supervisor tree contains a non-root-owned symlink"
  find "$supervisor_root" -xdev -type l -exec sh -c '
    root=$1
    shift
    for link do
      target=$(readlink -f -- "$link") || exit 1
      case "$target" in
        "$root"/*) ;;
        *) exit 1 ;;
      esac
    done
  ' sh "$supervisor_root" {} + \
    || fail "pinned supervisor tree has a broken or escaping symlink"
}

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh --config /absolute/path/validator-supervisor.json \
  --bootstrap-result-upload-key /absolute/path/bootstrap-result-upload.key \
  (--fresh-install | --legacy-unit EXACT_SYSTEM_SERVICE.service)

Use --fresh-install only when this host has no existing SN78 weight writer.
That mode does not inspect, stop, disable, mask, or invent a legacy service.

The legacy mode accepts one exact systemd system service. It does not inspect
or stop containers, PM2 applications, user services, cron jobs, or matched
process names.
EOF
}

[ "$(id -u)" -eq 0 ] || fail "run this installer as root"

config_source=
bootstrap_upload_credential_source=
install_mode=
legacy_unit=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      [ "$#" -ge 2 ] || fail "--config requires one absolute path"
      config_source=$2
      shift 2
      ;;
    --bootstrap-result-upload-key)
      [ "$#" -ge 2 ] || fail "--bootstrap-result-upload-key requires one absolute path"
      bootstrap_upload_credential_source=$2
      shift 2
      ;;
    --legacy-unit)
      [ "$#" -ge 2 ] || fail "--legacy-unit requires one service name"
      [ -z "$install_mode" ] \
        || fail "choose exactly one of --fresh-install or --legacy-unit"
      install_mode=legacy
      legacy_unit=$2
      shift 2
      ;;
    --fresh-install)
      [ -z "$install_mode" ] \
        || fail "choose exactly one of --fresh-install or --legacy-unit"
      install_mode=fresh
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument"
      ;;
  esac
done

[ -n "$config_source" ] || fail "--config is required"
[ -n "$bootstrap_upload_credential_source" ] \
  || fail "--bootstrap-result-upload-key is required"
[ -n "$install_mode" ] \
  || fail "choose exactly one of --fresh-install or --legacy-unit"
case "$config_source" in
  /*) ;;
  *) fail "--config must be an absolute path" ;;
esac
case "$bootstrap_upload_credential_source" in
  /*) ;;
  *) fail "--bootstrap-result-upload-key must be an absolute path" ;;
esac
if [ "$install_mode" = legacy ]; then
  case "$legacy_unit" in
    *.service) ;;
    *) fail "legacy unit must include the .service suffix" ;;
  esac
  case "$legacy_unit" in
    ''|*/*|*[!A-Za-z0-9_.@-]*) fail "legacy unit name is invalid" ;;
  esac
  [ "$legacy_unit" != "$service_name" ] || fail "refusing to retire the UMI supervisor"
fi

[ -f "$config_source" ] || fail "config source is not a regular file"
[ ! -L "$config_source" ] || fail "config source must not be a symlink"
case "$(stat -c '%a' "$config_source")" in
  400|440|600|640) ;;
  *) fail "config source mode must be 0400, 0440, 0600, or 0640" ;;
esac
[ -f "$bootstrap_upload_credential_source" ] \
  || fail "bootstrap result upload key source is not a regular file"
[ ! -L "$bootstrap_upload_credential_source" ] \
  || fail "bootstrap result upload key source must not be a symlink"
[ "$(stat -c '%h' "$bootstrap_upload_credential_source")" -eq 1 ] \
  || fail "bootstrap result upload key source must not be hard-linked"
case "$(stat -c '%a' "$bootstrap_upload_credential_source")" in
  400|600) ;;
  *) fail "bootstrap result upload key source mode must be 0400 or 0600" ;;
esac
credential_source_size=$(stat -c '%s' "$bootstrap_upload_credential_source")
case "$credential_source_size" in
  64|65) ;;
  *) fail "bootstrap result upload key must encode exactly 32 bytes" ;;
esac
LC_ALL=C grep -Eq '^[0-9a-f]{64}$' "$bootstrap_upload_credential_source" \
  || fail "bootstrap result upload key must be 64 lowercase hexadecimal characters"
[ -f "$service_source" ] || fail "checked-in service unit is missing"
[ ! -L "$service_source" ] || fail "checked-in service unit must not be a symlink"
[ -f "$subordinate_range_checker" ] \
  || fail "checked-in subordinate-ID range checker is missing"
[ ! -L "$subordinate_range_checker" ] \
  || fail "checked-in subordinate-ID range checker must not be a symlink"
[ "$(stat -c '%u' "$service_source")" -eq 0 ] \
  || fail "checked-in service unit must be owned by root"
service_source_mode=$(stat -c '%a' "$service_source")
[ "$((0$service_source_mode & 0022))" -eq 0 ] \
  || fail "checked-in service unit is group- or world-writable"
[ "$((0$service_source_mode & 07000))" -eq 0 ] \
  || fail "checked-in service unit has special permission bits"
[ -d "$supervisor_root" ] && [ ! -L "$supervisor_root" ] \
  || fail "pinned supervisor root must be a real directory"
[ "$(readlink -f "$supervisor_root")" = "$supervisor_root" ] \
  || fail "pinned supervisor root must not traverse symlinks"
require_immutable_supervisor_tree
[ -x "$supervisor_executable" ] || fail "pinned supervisor executable is missing"
[ ! -L "$supervisor_executable" ] || fail "supervisor executable must not be a symlink"
[ "$(readlink -f "$supervisor_executable")" = "$supervisor_executable" ] \
  || fail "supervisor executable path must not traverse symlinks"
[ "$(stat -c '%u' "$supervisor_executable")" -eq 0 ] \
  || fail "supervisor executable must be owned by root"
executable_mode=$(stat -c '%a' "$supervisor_executable")
[ "$((0$executable_mode & 0022))" -eq 0 ] \
  || fail "supervisor executable is group- or world-writable"
[ "$((0$executable_mode & 07000))" -eq 0 ] \
  || fail "supervisor executable has special permission bits"
[ -x "$container_runtime" ] || fail "rootless Podman is not installed at /usr/bin/podman"
[ -x "$slirp4netns_binary" ] \
  || fail "rootless Podman networking is not installed at /usr/bin/slirp4netns"

if [ "$install_mode" = legacy ]; then
  load_state=$(systemctl show "$legacy_unit" --property=LoadState --value)
  [ "$load_state" = loaded ] || fail "legacy unit is not one loaded system service"
  legacy_fragment=$(systemctl show "$legacy_unit" --property=FragmentPath --value)
  case "$legacy_fragment" in
    /*) ;;
    *) fail "legacy unit fragment path is missing or non-absolute" ;;
  esac
  legacy_control_group=$(systemctl show "$legacy_unit" --property=ControlGroup --value)
  case "$legacy_control_group" in
    ''|/*) ;;
    *) fail "legacy unit control group is invalid" ;;
  esac
  [ -f "$legacy_fragment" ] || fail "legacy unit fragment is not a regular file"
  [ ! -L "$legacy_fragment" ] || fail "legacy unit fragment must not be a symlink"
  case "$legacy_fragment" in
    "/etc/systemd/system/$legacy_unit")
      archive_path="$archive_root/$legacy_unit"
      [ ! -e "$archive_path" ] && [ ! -L "$archive_path" ] \
        || fail "retired-unit archive already exists"
      ;;
    /etc/systemd/system/*)
      fail "legacy unit uses an unexpected local fragment path"
      ;;
  esac
fi

if ! getent group "$service_account" >/dev/null 2>&1; then
  groupadd --system "$service_account"
fi
if ! id "$service_account" >/dev/null 2>&1; then
  useradd --system --gid "$service_account" --no-create-home \
    --home-dir /var/lib/umi-validator-supervisor --shell /usr/sbin/nologin \
    "$service_account"
fi
[ "$(id -gn "$service_account")" = "$service_account" ] \
  || fail "existing service account has an unexpected primary group"
service_uid=$(id -u "$service_account")
[ "$service_uid" -gt 0 ] || fail "service account must not be UID 0"
[ "$(id -g "$service_account")" -gt 0 ] || fail "service group must not be GID 0"
[ "$(getent passwd "$service_account" | cut -d: -f6)" = /var/lib/umi-validator-supervisor ] \
  || fail "service account has an unexpected home directory"
case "$(getent passwd "$service_account" | cut -d: -f7)" in
  /usr/sbin/nologin|/sbin/nologin) ;;
  *) fail "service account must use a nologin shell" ;;
esac

[ ! -e "$config_destination" ] && [ ! -L "$config_destination" ] \
  || fail "installed supervisor config already exists"
[ ! -e "$service_destination" ] && [ ! -L "$service_destination" ] \
  || fail "installed supervisor service already exists"
[ ! -e "$bootstrap_upload_credential" ] && [ ! -L "$bootstrap_upload_credential" ] \
  || fail "installed bootstrap result upload key already exists"

for managed_directory in \
  /etc/umi \
  /var/lib/umi-validator-runtime-wallets \
  /var/lib/umi-validator-operator-inputs \
  "$bootstrap_upload_root" \
  /var/lib/umi-validator-supervisor \
  /var/lib/umi-validator-supervisor/container-config \
  /var/lib/umi-validator-supervisor/container-data \
  /var/lib/umi-validator-supervisor/home \
  /var/lib/umi-validator-supervisor/state \
  /var/lib/umi-validator-supervisor/releases \
  /var/lib/umi-validator-worker-state \
  /run/umi-validator-supervisor \
  "$archive_root"
do
  require_real_directory_target "$managed_directory"
done

install -d -o root -g root -m 0755 /etc/umi
install -d -o root -g "$service_account" -m 0750 /var/lib/umi-validator-runtime-wallets
install -d -o "$service_account" -g "$service_account" -m 0700 \
  "$bootstrap_upload_root"
install -d -o "$service_account" -g "$service_account" -m 0700 \
  /var/lib/umi-validator-operator-inputs \
  /var/lib/umi-validator-supervisor \
  /var/lib/umi-validator-supervisor/container-config \
  /var/lib/umi-validator-supervisor/container-data \
  /var/lib/umi-validator-supervisor/home \
  /var/lib/umi-validator-supervisor/state \
  /var/lib/umi-validator-supervisor/releases \
  /var/lib/umi-validator-worker-state
install -d -o "$service_account" -g "$service_account" -m 0700 \
  /run/umi-validator-supervisor

for initially_empty_directory in \
  /var/lib/umi-validator-supervisor/state \
  /var/lib/umi-validator-worker-state
do
  initial_state_entry=$(
    find "$initially_empty_directory" -mindepth 1 -maxdepth 1 -print -quit
  ) || fail "could not inspect an initial state directory"
  [ -z "$initial_state_entry" ] \
    || fail "initial state directory is not empty: $initially_empty_directory"
done

for subordinate_file in /etc/subuid /etc/subgid; do
  require_private_subordinate_range "$subordinate_file"
done
[ "$(id -nG "$service_account")" = "$service_account" ] \
  || fail "service account must not belong to supplementary groups"

config_stage="/etc/umi/.validator-supervisor.json.installing.$$"
credential_stage="$bootstrap_upload_root/.bootstrap-result-upload.key.installing.$$"
cleanup_stage() {
  rm -f -- "$config_stage" "$credential_stage"
}
trap cleanup_stage EXIT HUP INT TERM
install -o root -g "$service_account" -m 0640 "$config_source" "$config_stage"
install -o "$service_account" -g "$service_account" -m 0400 \
  "$bootstrap_upload_credential_source" "$credential_stage"

supervisor() {
  runuser -u "$service_account" -- env -i \
    HOME=/var/lib/umi-validator-supervisor/home \
    XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
    XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
    XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
    LOGNAME="$service_account" \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    USER="$service_account" \
    "$supervisor_executable" "$@"
}

supervisor check-config --config "$config_stage" --profile linux-systemd-v1
systemd-analyze verify "$service_source"

podman() {
  runuser -u "$service_account" -- env -i \
    HOME=/var/lib/umi-validator-supervisor/home \
    XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
    XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
    XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
    LOGNAME="$service_account" \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    USER="$service_account" \
    "$container_runtime" "$@"
}

[ "$(podman info --format '{{.Host.Security.Rootless}}')" = true ] \
  || fail "Podman did not report a rootless service context"
[ "$(podman info --format '{{.Host.CgroupsVersion}}')" = v2 ] \
  || fail "rootless Podman requires cgroup v2 for the signed resource ceilings"
case "$(podman info --format '{{.Store.GraphRoot}}')" in
  /var/lib/umi-validator-supervisor/container-data/*) ;;
  *) fail "rootless Podman graph root escaped the supervisor state tree" ;;
esac
case "$(podman info --format '{{.Store.RunRoot}}')" in
  /run/umi-validator-supervisor/*) ;;
  *) fail "rootless Podman run root escaped the supervisor runtime tree" ;;
esac
podman unshare /usr/bin/true \
  || fail "rootless Podman user-namespace preflight failed"

# This is the last preflight before the installation boundary. It
# fetches and authenticates the validator-bound sequence-1 hold directive and
# reads a fresh finalized Finney head through the owned verifier. It does not
# write supervisor state or start a worker.
supervisor preflight-initial-hold --config "$config_stage"

if [ "$install_mode" = legacy ]; then
  systemctl disable --now "$legacy_unit"
  if systemctl is-active --quiet "$legacy_unit"; then
    fail "legacy unit remained active after stop"
  fi

  case "$legacy_fragment" in
    "/etc/systemd/system/$legacy_unit")
      install -d -o root -g root -m 0700 "$archive_root"
      mv -- "$legacy_fragment" "$archive_path"
      chmod 0600 "$archive_path"
      systemctl daemon-reload
      ;;
  esac

  systemctl mask "$legacy_unit"
  masked_state=$(systemctl is-enabled "$legacy_unit" 2>/dev/null || :)
  [ "$masked_state" = masked ] || fail "legacy unit is not permanently masked"
  # KillMode=process and KillMode=mixed can leave children behind after a clean
  # stop. The unit is masked before this exact-cgroup kill, so it cannot restart
  # while the installer checks every descendant cgroup.
  systemctl kill --kill-whom=all --signal=SIGKILL "$legacy_unit" >/dev/null 2>&1 || :
  if systemctl is-active --quiet "$legacy_unit"; then
    fail "legacy unit became active after masking"
  fi
  legacy_main_pid=$(systemctl show "$legacy_unit" --property=MainPID --value)
  [ "$legacy_main_pid" = 0 ] || fail "legacy unit still has a main process after masking"
  require_empty_unit_control_group "$legacy_control_group"
  current_legacy_control_group=$(
    systemctl show "$legacy_unit" --property=ControlGroup --value
  )
  require_empty_unit_control_group "$current_legacy_control_group"
fi

mv -- "$credential_stage" "$bootstrap_upload_credential"
mv -- "$config_stage" "$config_destination"
install -o root -g root -m 0644 "$service_source" "$service_destination"
trap - EXIT HUP INT TERM
systemctl daemon-reload
systemctl enable --now "$service_name"
readiness_attempt=0
stable_hold_observations=0
supervisor_ready=false
while [ "$readiness_attempt" -lt 180 ]; do
  if systemctl is-active --quiet "$service_name" && \
    supervisor status --config "$config_destination" --require-hold \
      >/dev/null 2>&1
  then
    stable_hold_observations=$((stable_hold_observations + 1))
    if [ "$stable_hold_observations" -ge 5 ]; then
      supervisor_ready=true
      break
    fi
  else
    stable_hold_observations=0
  fi
  readiness_attempt=$((readiness_attempt + 1))
  sleep 1
done
[ "$supervisor_ready" = true ] \
  || fail "UMI supervisor did not establish its singleton hold"

printf 'install_mode=%s\n' "$install_mode"
if [ "$install_mode" = legacy ]; then
  printf 'legacy_unit=%s\n' "$legacy_unit"
  printf 'legacy_unit_state=masked_inactive\n'
else
  printf 'legacy_action=none\n'
fi
printf 'supervisor_state=durable_hold\n'
