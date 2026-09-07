#!/bin/sh

set -eu
umask 077

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_directory/../.." && pwd -P)
compose_file="$script_directory/compose.yaml"
clean_compose_environment="$script_directory/clean-compose-environment.sh"

fail() {
  printf 'umi-macos-validator: %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Usage: manage.sh --env-file FILE COMMAND

Commands:
  build             Build the revision-bound validator and audit-origin images.
  preflight         Verify macOS, Apple Silicon, Docker, Compose, and the image.
  initialize        Initialize persistent Linux volumes without deleting data.
  account-id        Print the validator hotkey's decoded AccountId32 hex.
  verify            Verify the complete signed inactive release.
  materialize       Materialize private startup configuration once.
  prime             Prime the next window before its announcement.
  check             Run the complete no-write validator startup check.
  start             Start the weight-disabled validator in the background.
  reconcile WINDOW  Reconcile one certificate-breach window without scoring.
  status            Show bounded container status.
  logs              Follow validator logs.
  stop              Stop the validator without deleting files.
  audit-check       Check the wallet-isolated audit publisher.
  audit-once        Publish any complete terminal bundle and exit.
  audit-start       Start the audit publisher in the background.
  audit-origin-start Start the loopback-only static audit origin.
  audit-logs        Follow audit-publisher logs.
  audit-stop        Stop the audit publisher without deleting files.
EOF
}

[ "${1:-}" = "--env-file" ] || { usage >&2; exit 2; }
[ "$#" -ge 3 ] || { usage >&2; exit 2; }
env_file=$2
command_name=$3
case "$command_name" in
  reconcile)
    [ "$#" -eq 4 ] || fail "reconcile requires one 64-character window ID"
    recovery_window_id=$4
    case "$recovery_window_id" in
      *[!0-9a-f]*|'') fail "recovery window ID must be lowercase hexadecimal" ;;
    esac
    [ "${#recovery_window_id}" -eq 64 ] \
      || fail "recovery window ID must encode 32 bytes"
    ;;
  *)
    [ "$#" -eq 3 ] || fail "unexpected arguments"
    ;;
esac
[ -f "$env_file" ] && [ ! -L "$env_file" ] || fail "env file must be a regular file"

case "$(uname -s)" in
  Darwin) ;;
  *) fail "this launcher is for macOS" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) ;;
  *) fail "this launcher requires Apple Silicon" ;;
esac

mode=$(/usr/bin/stat -f '%Lp' "$env_file")
case "$mode" in
  400|600) ;;
  *) fail "env file mode must be 0400 or 0600" ;;
esac
[ "$(/usr/bin/stat -f '%u' "$env_file")" = "$(id -u)" ] \
  || fail "env file must be owned by the invoking user"

read_env_value() {
  key=$1
  /usr/bin/awk -v key="$key" '
    index($0, key "=") == 1 {
      count += 1
      value = substr($0, length(key) + 2)
    }
    END {
      if (count != 1) {
        exit 2
      }
      print value
    }
  ' "$env_file" || fail "$key must appear exactly once as KEY=value"
}

deployment_id=$(read_env_value UMI_DEPLOYMENT_ID)
case "$deployment_id" in
  ''|*[!a-z0-9-]*|-*|*-) \
    fail "UMI_DEPLOYMENT_ID must use lowercase letters, digits, and internal hyphens only" ;;
esac
[ "${#deployment_id}" -le 48 ] \
  || fail "UMI_DEPLOYMENT_ID must be at most 48 characters"
compose_project="umi-macos-validator-$deployment_id"

command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is unavailable"
[ -x "$clean_compose_environment" ] \
  || fail "clean Compose environment launcher is missing or not executable"

compose() {
  "$clean_compose_environment" docker compose \
    --project-name "$compose_project" \
    --env-file "$env_file" --file "$compose_file" "$@"
}

one_shot() {
  service=$1
  command=$2
  compose run --rm --no-deps --pull never "$service" "$command"
}

active_service_ids() {
  service=$1
  compose ps --quiet \
    --status running --status restarting --status paused "$service"
}

case "$command_name" in
  build)
    [ -z "$(git -C "$repository_root" status --porcelain)" ] \
      || fail "the UMI checkout must be clean before building a revision-bound image"
    revision=$(git -C "$repository_root" rev-parse --verify HEAD)
    [ "$(read_env_value UMI_GIT_REVISION)" = "$revision" ] \
      || fail "UMI_GIT_REVISION in the env file must equal the clean checkout HEAD"
    [ "$(read_env_value UMI_VALIDATOR_IMAGE)" = "umi-validator:$revision" ] \
      || fail "UMI_VALIDATOR_IMAGE must be umi-validator:<UMI_GIT_REVISION>"
    compose build --pull validator audit-origin
    printf 'built_revision=%s\n' "$revision"
    ;;
  preflight)
    docker info >/dev/null 2>&1 || fail "Docker's Linux VM is not running"
    compose config --quiet
    one_shot bootstrap version
    ;;
  initialize)
    [ -z "$(active_service_ids validator)" ] \
      || fail "stop the validator before initializing persistent volumes"
    compose run --rm --no-deps --pull never volume-init init-volumes
    ;;
  account-id|verify)
    one_shot bootstrap "$command_name"
    ;;
  materialize|prime)
    [ -z "$(active_service_ids validator)" ] \
      || fail "stop the validator before $command_name"
    one_shot bootstrap "$command_name"
    ;;
  check)
    [ -z "$(active_service_ids validator)" ] \
      || fail "stop the validator before check"
    one_shot validator check
    ;;
  start)
    compose up --detach --no-deps --no-build --pull never validator
    ;;
  reconcile)
    [ -z "$(active_service_ids validator)" ] \
      || fail "stop the validator before reconcile"
    [ -z "$(active_service_ids audit-publisher)" ] \
      || fail "stop the audit publisher before reconcile"
    compose run --rm --no-deps --pull never \
      --env "UMI_RECOVERY_WINDOW_ID=$recovery_window_id" bootstrap reconcile
    ;;
  status)
    compose ps validator audit-publisher audit-origin
    ;;
  logs)
    compose logs --follow --tail 200 validator
    ;;
  stop)
    compose stop validator
    ;;
  audit-check|audit-once)
    [ -z "$(active_service_ids audit-publisher)" ] \
      || fail "stop the audit publisher before $command_name"
    one_shot audit-publisher "$command_name"
    ;;
  audit-start)
    compose up --detach --no-deps --no-build audit-origin
    compose up --detach --no-deps --no-build --pull never audit-publisher
    ;;
  audit-origin-start)
    compose up --detach --no-deps --no-build audit-origin
    ;;
  audit-logs)
    compose logs --follow --tail 200 audit-publisher
    ;;
  audit-stop)
    compose stop audit-publisher audit-origin
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage >&2
    fail "unknown command: $command_name"
    ;;
esac
