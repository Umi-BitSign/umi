#!/bin/sh

set -eu
umask 077

podman() {
  /usr/bin/env -i \
    CONTAINERS_CONF_OVERRIDE=/opt/umi-validator-supervisor/deploy/linux-validator-supervisor/containers.conf \
    HOME=/var/lib/umi-validator-supervisor/home \
    XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
    XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
    XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
    LOGNAME=umi-validator \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    USER=umi-validator \
    /usr/bin/timeout --signal=TERM --kill-after=5s 60s \
    /usr/bin/podman "$@"
}

fail() {
  printf 'podman-runtime-smoke: %s\n' "$*" >&2
  exit 2
}

smoke_mount_root=/var/lib/umi-validator-runtime-smoke
readonly_mount="$smoke_mount_root/readonly"
readwrite_mount="$smoke_mount_root/readwrite"
service_uid=$(/usr/bin/id -u)
service_gid=$(/usr/bin/id -g)
[ ! -L "$smoke_mount_root" ] && [ -d "$smoke_mount_root" ] \
  && [ "$(/usr/bin/stat -c '%u:%g:%a' "$smoke_mount_root")" = '0:0:755' ] \
  || fail "dummy mount root is unsafe"
[ ! -L "$readonly_mount" ] && [ -d "$readonly_mount" ] \
  && [ "$(/usr/bin/stat -c '%u:%g:%a' "$readonly_mount")" = '0:0:555' ] \
  || fail "read-only dummy mount is unsafe"
[ ! -L "$readwrite_mount" ] && [ -d "$readwrite_mount" ] \
  && [ "$(/usr/bin/stat -c '%u:%g:%a' "$readwrite_mount")" \
    = "$service_uid:$service_gid:700" ] \
  || fail "read-write dummy mount is unsafe"

require_empty_dummy_mounts() {
  unexpected=$(/usr/bin/find "$smoke_mount_root" -mindepth 2 -print -quit) \
    || fail "could not inspect dummy mounts"
  [ -z "$unexpected" ] || fail "dummy mounts are not empty"
}

# The installer has already staged and verified at least one signed worker in
# this isolated store. Pick one only as a root filesystem for an inert runtime
# check. The fixed dummy binds and production network driver contain no secrets;
# no image entrypoint, wallet, operator input, worker state, or signing path runs.
# The fixed shell expression proves that rootless cgroupfs actually enforces the
# three per-container limits rather than silently accepting and ignoring them.
require_empty_dummy_mounts
image_id=$(podman image list --no-trunc --format '{{.ID}}' | /usr/bin/sed -n '1p')
case "$image_id" in
  sha256:*) image_digest=${image_id#sha256:} ;;
  *) image_digest=$image_id ;;
esac
[ "${#image_digest}" -eq 64 ] \
  || { printf '%s\n' 'podman runtime smoke found no full image ID' >&2; exit 2; }
case "$image_digest" in
  *[!0-9a-f]*) printf '%s\n' 'podman runtime smoke found an invalid image ID' >&2; exit 2 ;;
esac

podman run --rm \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --image-volume=ignore \
  --pull=never \
  --userns keep-id:uid=65532,gid=65532 \
  --user 65532:65532 \
  --cpus 1 \
  --memory 268435456 \
  --pids-limit 16 \
  --network slirp4netns:allow_host_loopback=false \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16777216 \
  --mount "type=bind,src=$readonly_mount,dst=/run/umi-smoke-readonly,ro=true,bind-propagation=private" \
  --mount "type=bind,src=$readwrite_mount,dst=/run/umi-smoke-readwrite,ro=false,bind-propagation=private" \
  --entrypoint /bin/sh \
  "$image_id" -eu -c '
    [ "$(cat /sys/fs/cgroup/memory.max)" = 268435456 ]
    [ "$(cat /sys/fs/cgroup/pids.max)" = 16 ]
    set -- $(cat /sys/fs/cgroup/cpu.max)
    [ "$1" != max ]
    [ "$1" = "$2" ]
  '

require_empty_dummy_mounts
