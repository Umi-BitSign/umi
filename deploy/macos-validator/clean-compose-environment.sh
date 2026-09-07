#!/bin/sh

# Compose gives ambient shell variables precedence over --env-file. Remove every
# deployment value consumed by compose.yaml so the reviewed mode-0600 file is the
# sole source. Preserve Docker context/auth variables and ordinary host settings.
set -eu

exec /usr/bin/env \
  -u COMPOSE_PROJECT_NAME \
  -u UMI_AUDIT_ORIGIN_PORT \
  -u UMI_AUDIT_PUBLISHER_INPUT_ROOT \
  -u UMI_DEPLOYMENT_ID \
  -u UMI_EXPECTED_AUTHORITY_HOTKEY \
  -u UMI_GIT_REVISION \
  -u UMI_HOST_GID \
  -u UMI_HOST_UID \
  -u UMI_OPERATOR_INPUT_ROOT \
  -u UMI_RELEASE_ROOT \
  -u UMI_VALIDATOR_ACCOUNT_HEX \
  -u UMI_VALIDATOR_CPUS \
  -u UMI_VALIDATOR_HOTKEY \
  -u UMI_VALIDATOR_IMAGE \
  -u UMI_VALIDATOR_MEMORY_LIMIT \
  -u UMI_VALIDATOR_PLATFORM \
  -u UMI_WALLET_ROOT \
  UMI_HOST_UID="$(id -u)" \
  UMI_HOST_GID="$(id -g)" \
  "$@"
