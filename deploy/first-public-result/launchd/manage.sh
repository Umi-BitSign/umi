#!/bin/sh

set -eu
umask 077

OBSERVER_LABEL="vision.umi.observer"
CLOUDFLARED_LABEL="vision.umi.cloudflared"
OBSERVER_PLIST_NAME="${OBSERVER_LABEL}.plist"
CLOUDFLARED_PLIST_NAME="${CLOUDFLARED_LABEL}.plist"
LAUNCH_DAEMON_DIRECTORY="/Library/LaunchDaemons"
OBSERVER_PORT="8092"
CLOUDFLARED_METRICS_PORT="49092"

fail() {
  printf 'umi-launchd: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  manage.sh render --output-dir DIRECTORY [options]
  manage.sh install [--replace] [--check-public-edge] [options]
  manage.sh check [--check-public-edge] [options]

Options:
  --repo-root DIRECTORY
  --observer-bin FILE
  --cloudflared-bin FILE
  --token-file FILE
  --bundle-feed-config FILE
  --output-dir DIRECTORY       Required only by render.
  --replace                    Replace different installed plists with rollback.
  --check-public-edge          Require a permanent HTTP redirect and HTTPS HSTS.

Run this script as the macOS account that should own both processes. The install
command invokes sudo only for the system launchd operations. It never reads,
prints, copies, or removes the tunnel token.
EOF
}

require_argument() {
  [ "$#" -ge 2 ] || fail "$1 requires a value"
}

absolute_directory() {
  [ -d "$1" ] || fail "directory does not exist: $1"
  (CDPATH= cd -- "$1" && /bin/pwd -P)
}

absolute_file() {
  path=$1
  [ -f "$path" ] || fail "regular file does not exist: $path"
  [ ! -L "$path" ] || fail "symbolic links are not accepted here: $path"
  directory=$(absolute_directory "$(/usr/bin/dirname -- "$path")")
  printf '%s/%s\n' "$directory" "$(/usr/bin/basename -- "$path")"
}

require_executable() {
  [ -x "$1" ] || fail "executable does not exist or is not executable: $1"
  case "$1" in
    /*) ;;
    *) fail "executable path is not absolute: $1" ;;
  esac
}

require_private_file() {
  path=$(absolute_file "$1")
  owner=$(/usr/bin/stat -f '%u' "$path")
  links=$(/usr/bin/stat -f '%l' "$path")
  mode=$(/usr/bin/stat -f '%Lp' "$path")
  [ "$owner" = "$(/usr/bin/id -u)" ] || fail "private file is not owned by the service user: $path"
  [ "$links" = "1" ] || fail "private file has more than one hard link: $path"
  case "$mode" in
    400 | 600) ;;
    *) fail "private file mode must be 0400 or 0600: $path" ;;
  esac
  printf '%s\n' "$path"
}

plist_replace_string() {
  file=$1
  key=$2
  value=$3
  /usr/bin/plutil -replace "$key" -string "$value" "$file" >/dev/null
}

plist_replace_array_string() {
  file=$1
  key=$2
  value=$3
  /usr/bin/plutil -remove "$key" "$file" >/dev/null
  /usr/bin/plutil -insert "$key" -string "$value" "$file" >/dev/null
}

render_plists() {
  destination=$1
  [ ! -e "$destination/$OBSERVER_PLIST_NAME" ] || fail "render target already exists: $destination/$OBSERVER_PLIST_NAME"
  [ ! -e "$destination/$CLOUDFLARED_PLIST_NAME" ] || fail "render target already exists: $destination/$CLOUDFLARED_PLIST_NAME"
  /bin/mkdir -p -- "$destination"

  observer_output="$destination/$OBSERVER_PLIST_NAME"
  cloudflared_output="$destination/$CLOUDFLARED_PLIST_NAME"
  /bin/cp -- "$SCRIPT_DIRECTORY/vision.umi.observer.plist.in" "$observer_output"
  /bin/cp -- "$SCRIPT_DIRECTORY/vision.umi.cloudflared.plist.in" "$cloudflared_output"

  # On current macOS, plutil's array `-replace` inserts and shifts the old
  # element. Removing the exact element first makes the operation unambiguous.
  plist_replace_array_string "$observer_output" ProgramArguments.0 "$observer_binary"
  plist_replace_string "$observer_output" UserName "$service_user"
  plist_replace_string "$observer_output" GroupName "$service_group"
  plist_replace_string "$observer_output" WorkingDirectory "$repository_root"
  plist_replace_string "$observer_output" EnvironmentVariables.HOME "$service_home"
  plist_replace_string "$observer_output" EnvironmentVariables.BITTENSOR_RUNTIME_CACHE_DIR "$runtime_cache"
  plist_replace_string "$observer_output" StandardOutPath "$log_directory/observer.launchd.out.log"
  plist_replace_string "$observer_output" StandardErrorPath "$log_directory/observer.launchd.err.log"

  if [ -n "$bundle_feed_config" ]; then
    /usr/bin/plutil -insert ProgramArguments -string '--bundle-feed-config' -append "$observer_output" >/dev/null
    /usr/bin/plutil -insert ProgramArguments -string "$bundle_feed_config" -append "$observer_output" >/dev/null
  fi

  plist_replace_array_string "$cloudflared_output" ProgramArguments.0 "$cloudflared_binary"
  plist_replace_array_string "$cloudflared_output" ProgramArguments.9 "$token_file"
  plist_replace_string "$cloudflared_output" UserName "$service_user"
  plist_replace_string "$cloudflared_output" GroupName "$service_group"
  plist_replace_string "$cloudflared_output" EnvironmentVariables.HOME "$service_home"
  plist_replace_string "$cloudflared_output" StandardOutPath "$log_directory/cloudflared.launchd.out.log"
  plist_replace_string "$cloudflared_output" StandardErrorPath "$log_directory/cloudflared.launchd.err.log"

  /usr/bin/plutil -lint "$observer_output" "$cloudflared_output" >/dev/null
  if /usr/bin/grep -q 'REPLACE_WITH' "$observer_output" "$cloudflared_output"; then
    fail "rendered plist retains a placeholder"
  fi
}

service_is_loaded() {
  /bin/launchctl print "system/$1" >/dev/null 2>&1
}

sudo_service_is_loaded() {
  /usr/bin/sudo /bin/launchctl print "system/$1" >/dev/null 2>&1
}

wait_for_url() {
  url=$1
  host_header=${2:-}
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    if [ -n "$host_header" ]; then
      if /usr/bin/curl --fail --silent --show-error --max-time 3 -H "Host: $host_header" "$url" >/dev/null 2>&1; then
        return 0
      fi
    elif /usr/bin/curl --fail --silent --show-error --max-time 3 "$url" >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    /bin/sleep 1
  done
  return 1
}

check_public_edge() {
  work=$1
  http_headers="$work/public-http.headers"
  https_headers="$work/public-https.headers"
  request_path='/api/v1/status?launchd-check=1'
  expected_location="https://api.umi.vision$request_path"

  /usr/bin/curl --silent --show-error --head --max-time 15 \
    --dump-header "$http_headers" --output /dev/null \
    "http://api.umi.vision$request_path"
  /usr/bin/grep -Eq '^HTTP/[^ ]+ (301|308)([[:space:]]|$)' "$http_headers" || fail "public HTTP endpoint does not return a permanent redirect"
  /usr/bin/grep -Fiq "Location: $expected_location" "$http_headers" || fail "public HTTP redirect does not preserve path and query"

  /usr/bin/curl --fail --silent --show-error --head --max-time 15 \
    --dump-header "$https_headers" --output /dev/null \
    "https://api.umi.vision$request_path"
  /usr/bin/grep -Eiq '^strict-transport-security:[[:space:]]*max-age=[1-9][0-9]*' "$https_headers" || fail "public HTTPS endpoint does not return a nonzero HSTS max-age"
}

check_installed_mode() {
  path=$1
  identity=$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$path")
  [ "$identity" = 'root:wheel:644' ] || fail "installed plist must be root:wheel mode 0644: $path ($identity)"
}

prepare_runtime_directories() {
  /bin/mkdir -p -- "$log_directory" "$runtime_cache"
  /bin/chmod 0700 "$log_directory" "$service_home/Library/Caches/umi-observer" "$runtime_cache"
}

check_private_directory() {
  path=$1
  [ -d "$path" ] && [ ! -L "$path" ] || fail "runtime directory is missing or is a symbolic link: $path"
  identity=$(/usr/bin/stat -f '%u:%Lp' "$path")
  [ "$identity" = "$(/usr/bin/id -u):700" ] || fail "runtime directory must be owned by the service user with mode 0700: $path"
}

check_runtime() {
  expected_directory=$1
  observer_target="$LAUNCH_DAEMON_DIRECTORY/$OBSERVER_PLIST_NAME"
  cloudflared_target="$LAUNCH_DAEMON_DIRECTORY/$CLOUDFLARED_PLIST_NAME"

  [ -f "$observer_target" ] || fail "observer LaunchDaemon is not installed"
  [ -f "$cloudflared_target" ] || fail "cloudflared LaunchDaemon is not installed"
  [ ! -L "$observer_target" ] || fail "installed observer plist is a symbolic link"
  [ ! -L "$cloudflared_target" ] || fail "installed cloudflared plist is a symbolic link"
  check_installed_mode "$observer_target"
  check_installed_mode "$cloudflared_target"
  /usr/bin/cmp -s "$expected_directory/$OBSERVER_PLIST_NAME" "$observer_target" || fail "installed observer plist differs from the rendered configuration"
  /usr/bin/cmp -s "$expected_directory/$CLOUDFLARED_PLIST_NAME" "$cloudflared_target" || fail "installed cloudflared plist differs from the rendered configuration"

  check_private_directory "$log_directory"
  check_private_directory "$service_home/Library/Caches/umi-observer"
  check_private_directory "$runtime_cache"

  service_is_loaded "$OBSERVER_LABEL" || fail "observer LaunchDaemon is not loaded"
  service_is_loaded "$CLOUDFLARED_LABEL" || fail "cloudflared LaunchDaemon is not loaded"
  wait_for_url "http://127.0.0.1:$OBSERVER_PORT/readyz" 'api.umi.vision' || fail "observer did not become ready"
  wait_for_url "http://127.0.0.1:$CLOUDFLARED_METRICS_PORT/ready" '' || fail "cloudflared has no ready tunnel connection"
}

legacy_screen_is_running() {
  /usr/bin/screen -ls 2>/dev/null | /usr/bin/grep -Eq '[.]umi-(observer|cloudflared)[[:space:]]'
}

port_is_listening() {
  /usr/sbin/lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

rollback_install() {
  set +e
  /usr/bin/sudo /bin/launchctl bootout "system/$CLOUDFLARED_LABEL" >/dev/null 2>&1
  /usr/bin/sudo /bin/launchctl bootout "system/$OBSERVER_LABEL" >/dev/null 2>&1

  if [ "$had_observer_plist" = 1 ]; then
    /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "$temporary_directory/previous-observer.plist" "$observer_target"
  else
    /usr/bin/sudo /bin/rm -f -- "$observer_target"
  fi
  if [ "$had_cloudflared_plist" = 1 ]; then
    /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "$temporary_directory/previous-cloudflared.plist" "$cloudflared_target"
  else
    /usr/bin/sudo /bin/rm -f -- "$cloudflared_target"
  fi

  if [ "$observer_was_loaded" = 1 ] && [ "$had_observer_plist" = 1 ]; then
    /usr/bin/sudo /bin/launchctl bootstrap system "$observer_target" >/dev/null 2>&1
  fi
  if [ "$cloudflared_was_loaded" = 1 ] && [ "$had_cloudflared_plist" = 1 ]; then
    /usr/bin/sudo /bin/launchctl bootstrap system "$cloudflared_target" >/dev/null 2>&1
  fi
  set -e
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "${temporary_directory:-}" ]; then
    /bin/rm -rf -- "$temporary_directory"
  fi
  if [ "${sudo_active:-0}" = 1 ]; then
    /usr/bin/sudo -k >/dev/null 2>&1
  fi
  exit "$status"
}

install_services() {
  rendered_directory=$1
  observer_target="$LAUNCH_DAEMON_DIRECTORY/$OBSERVER_PLIST_NAME"
  cloudflared_target="$LAUNCH_DAEMON_DIRECTORY/$CLOUDFLARED_PLIST_NAME"
  had_observer_plist=0
  had_cloudflared_plist=0
  observer_was_loaded=0
  cloudflared_was_loaded=0

  legacy_screen_is_running && fail "stop the umi-observer and umi-cloudflared screen sessions before installing"

  prepare_runtime_directories

  /usr/bin/sudo -v
  sudo_active=1
  if sudo_service_is_loaded "$OBSERVER_LABEL"; then observer_was_loaded=1; fi
  if sudo_service_is_loaded "$CLOUDFLARED_LABEL"; then cloudflared_was_loaded=1; fi

  if [ -e "$observer_target" ]; then
    [ -f "$observer_target" ] && [ ! -L "$observer_target" ] || fail "observer plist target is not one regular file"
    check_installed_mode "$observer_target"
    had_observer_plist=1
    /bin/cp -- "$observer_target" "$temporary_directory/previous-observer.plist"
    if ! /usr/bin/cmp -s "$rendered_directory/$OBSERVER_PLIST_NAME" "$observer_target" && [ "$replace_installed" != 1 ]; then
      fail "installed observer plist differs; review it and rerun with --replace"
    fi
  elif [ "$observer_was_loaded" = 0 ] && port_is_listening "$OBSERVER_PORT"; then
    fail "TCP port $OBSERVER_PORT is already in use"
  fi

  if [ -e "$cloudflared_target" ]; then
    [ -f "$cloudflared_target" ] && [ ! -L "$cloudflared_target" ] || fail "cloudflared plist target is not one regular file"
    check_installed_mode "$cloudflared_target"
    had_cloudflared_plist=1
    /bin/cp -- "$cloudflared_target" "$temporary_directory/previous-cloudflared.plist"
    if ! /usr/bin/cmp -s "$rendered_directory/$CLOUDFLARED_PLIST_NAME" "$cloudflared_target" && [ "$replace_installed" != 1 ]; then
      fail "installed cloudflared plist differs; review it and rerun with --replace"
    fi
  elif [ "$cloudflared_was_loaded" = 0 ] && port_is_listening "$CLOUDFLARED_METRICS_PORT"; then
    fail "TCP port $CLOUDFLARED_METRICS_PORT is already in use"
  fi

  if [ "$observer_was_loaded" = 1 ]; then
    if ! /usr/bin/sudo /bin/launchctl bootout "system/$OBSERVER_LABEL"; then
      fail "observer bootout failed before installation; no plist was changed"
    fi
  fi
  if [ "$cloudflared_was_loaded" = 1 ]; then
    if ! /usr/bin/sudo /bin/launchctl bootout "system/$CLOUDFLARED_LABEL"; then
      rollback_install
      fail "cloudflared bootout failed; previous launchd state was restored"
    fi
  fi

  if ! /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 \
    "$rendered_directory/$OBSERVER_PLIST_NAME" "$observer_target"; then
    rollback_install
    fail "observer plist installation failed; previous launchd state was restored"
  fi
  if ! /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 \
    "$rendered_directory/$CLOUDFLARED_PLIST_NAME" "$cloudflared_target"; then
    rollback_install
    fail "cloudflared plist installation failed; previous launchd state was restored"
  fi

  if ! /usr/bin/sudo /bin/launchctl bootstrap system "$observer_target"; then
    rollback_install
    fail "observer bootstrap failed; previous launchd state was restored"
  fi
  if ! wait_for_url "http://127.0.0.1:$OBSERVER_PORT/readyz" 'api.umi.vision'; then
    rollback_install
    fail "observer readiness failed; previous launchd state was restored"
  fi
  if ! /usr/bin/sudo /bin/launchctl bootstrap system "$cloudflared_target"; then
    rollback_install
    fail "cloudflared bootstrap failed; previous launchd state was restored"
  fi
  if ! wait_for_url "http://127.0.0.1:$CLOUDFLARED_METRICS_PORT/ready" ''; then
    rollback_install
    fail "cloudflared readiness failed; previous launchd state was restored"
  fi
}

[ "$(/usr/bin/uname -s)" = Darwin ] || fail "this script supports macOS only"
[ "$(/usr/bin/id -u)" -ne 0 ] || fail "run as the service account, not through sudo"
[ "$#" -ge 1 ] || { usage >&2; exit 2; }

command_name=$1
shift
case "$command_name" in
  render | install | check) ;;
  -h | --help | help) usage; exit 0 ;;
  *) usage >&2; fail "unknown command: $command_name" ;;
esac

SCRIPT_DIRECTORY=$(absolute_directory "$(/usr/bin/dirname -- "$0")")
repository_root=$(absolute_directory "$SCRIPT_DIRECTORY/../../..")
observer_binary=''
cloudflared_binary=''
token_file=''
bundle_feed_config=''
output_directory=''
replace_installed=0
check_edge=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-root)
      require_argument "$@"
      repository_root=$2
      shift 2
      ;;
    --observer-bin)
      require_argument "$@"
      observer_binary=$2
      shift 2
      ;;
    --cloudflared-bin)
      require_argument "$@"
      cloudflared_binary=$2
      shift 2
      ;;
    --token-file)
      require_argument "$@"
      token_file=$2
      shift 2
      ;;
    --bundle-feed-config)
      require_argument "$@"
      bundle_feed_config=$2
      shift 2
      ;;
    --output-dir)
      require_argument "$@"
      output_directory=$2
      shift 2
      ;;
    --replace)
      replace_installed=1
      shift
      ;;
    --check-public-edge)
      check_edge=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown option: $1"
      ;;
  esac
done

[ "$command_name" = install ] || [ "$replace_installed" = 0 ] || fail "--replace is valid only with install"
service_user=$(/usr/bin/id -un)
service_group=$(/usr/bin/id -gn)
service_home=$(/usr/bin/dscl . -read "/Users/$service_user" NFSHomeDirectory | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')
[ -n "$service_home" ] || fail "cannot resolve the service account home directory"
service_home=$(absolute_directory "$service_home")
repository_root=$(absolute_directory "$repository_root")
if [ -z "$observer_binary" ]; then observer_binary="$repository_root/.venv/bin/umi-observer"; fi
if [ -z "$cloudflared_binary" ]; then
  cloudflared_binary=$(command -v cloudflared || true)
  [ -n "$cloudflared_binary" ] || fail "cloudflared is not on PATH; pass --cloudflared-bin"
fi
require_executable "$observer_binary"
require_executable "$cloudflared_binary"
if [ -z "$token_file" ]; then token_file="$service_home/.cloudflared/umi-observer-api.token"; fi
token_file=$(require_private_file "$token_file")
if [ -n "$bundle_feed_config" ]; then bundle_feed_config=$(require_private_file "$bundle_feed_config"); fi

log_directory="$service_home/Library/Logs/UMI"
runtime_cache="$service_home/Library/Caches/umi-observer/bittensor-runtime"

temporary_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/umi-launchd.XXXXXX")
sudo_active=0
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$command_name" in
  render)
    [ -n "$output_directory" ] || fail "render requires --output-dir"
    case "$output_directory" in /*) ;; *) fail "output directory must be absolute" ;; esac
    render_plists "$output_directory"
    printf 'rendered_observer=%s/%s\n' "$output_directory" "$OBSERVER_PLIST_NAME"
    printf 'rendered_cloudflared=%s/%s\n' "$output_directory" "$CLOUDFLARED_PLIST_NAME"
    ;;
  install)
    [ -z "$output_directory" ] || fail "--output-dir is valid only with render"
    render_plists "$temporary_directory/rendered"
    install_services "$temporary_directory/rendered"
    check_runtime "$temporary_directory/rendered"
    if [ "$check_edge" = 1 ]; then check_public_edge "$temporary_directory"; fi
    printf 'launchdaemons_ready=2\n'
    ;;
  check)
    [ -z "$output_directory" ] || fail "--output-dir is valid only with render"
    render_plists "$temporary_directory/rendered"
    check_runtime "$temporary_directory/rendered"
    if [ "$check_edge" = 1 ]; then check_public_edge "$temporary_directory"; fi
    printf 'launchdaemons_healthy=2\n'
    ;;
esac
