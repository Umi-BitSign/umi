import json

import pytest

from umi.host_cpu_cgroupfs import cgroupfs_payload_directory, podman_parent_argument

PARENT = "/sys/fs/cgroup/umiexecution.slice/models/model-a.slot/uid993"
CID = "ab" * 32
NAME = "umi-evaluation-" + "cd" * 16


def inspection(path, **changes):
    return json.dumps(
        [dict(Id=CID, Name=NAME, State=dict(Running=True, CgroupPath=path), **changes)]
    ).encode()


def test_exact_mount_relative_parent_and_cgroupfs_payload():
    assert podman_parent_argument(PARENT) == PARENT.removeprefix("/sys/fs/cgroup")
    for path in (
        PARENT + "/libpod-" + CID,
        PARENT.removeprefix("/sys/fs/cgroup") + "/libpod-" + CID,
    ):
        assert (
            str(
                cgroupfs_payload_directory(
                    inspection(path), container_id=CID, name=NAME, owned_parent=PARENT
                )
            )
            == PARENT + "/libpod-" + CID
        )


@pytest.mark.parametrize(
    "path",
    [
        PARENT + "/libpod-" + CID + ".scope/container",
        PARENT + "/../other/libpod-" + CID,
        PARENT + "/libpod-" + "ef" * 32,
        "/other/libpod-" + CID,
    ],
)
def test_systemd_or_ambiguous_path_cannot_be_fallback_for_cgroupfs(path):
    with pytest.raises(ValueError):
        cgroupfs_payload_directory(
            inspection(path), container_id=CID, name=NAME, owned_parent=PARENT
        )
