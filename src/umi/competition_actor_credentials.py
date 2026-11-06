"""Delegate publication with the selected service's actual Unix credentials."""

from pathlib import Path


def selected_process_credentials(pid, uid):
    """Read kernel credentials, including systemd-only supplementary groups.

    The caller must first bind this PID to the selected service/configuration.
    Actor-side publication checks that binding again after privilege reduction.
    No account membership or directory permissions are changed.
    """
    with Path(f"/proc/{pid}/status").open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("selected actor credentials exceed metadata bound")
    fields = dict(line.split(":", 1) for line in raw.decode("ascii").splitlines() if ":" in line)
    uids = [int(value) for value in fields["Uid"].split()]
    gids = [int(value) for value in fields["Gid"].split()]
    groups = sorted({int(value) for value in fields["Groups"].split()})
    if uids != [uid] * 4 or len(gids) != 4 or len(set(gids)) != 1:
        raise ValueError("selected actor has inconsistent Unix credentials")
    if not all(0 <= value < 2**32 - 1 for value in [uid, *gids, *groups]):
        raise ValueError("selected actor has invalid Unix credentials")
    return {"user": uid, "group": gids[0], "extra_groups": groups}
