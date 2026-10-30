"""Sign one exact approval as its configured key owner; publish only in root."""

from __future__ import annotations

import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path

from .competition_reward_transition_controls import (
    MAX_APPROVAL_BYTES,
    RewardTransitionApproval,
    SignedRewardTransitionApproval,
)
from .competition_upgrade import _open_without_links
from .competition_work_progress import WorkProgress
from .named_hotkey import load_named_hotkey
from .native_process_group import native_start_new_session
from .open_competition import sign_object
from .protocol import canonical_json_bytes
from .substrate_proof import _communicate_bounded


def sign_operator_approval(
    config, body: RewardTransitionApproval
) -> SignedRewardTransitionApproval:
    """Keep key ownership intact and return only bounded signed public bytes."""
    if os.geteuid() != 0:
        raise ValueError("fresh operator approval requires its root publisher")
    path = Path(config.control_key_file)
    descriptor = _open_without_links(path)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o400
            or not 0 < info.st_size <= 128 * 1024
        ):
            raise ValueError("configured operator key metadata is unsafe")
        try:
            account = pwd.getpwuid(info.st_uid)
        except KeyError as error:
            raise ValueError("configured operator signer account is unavailable") from error
    finally:
        os.close(descriptor)
    raw = canonical_json_bytes(body)
    if len(raw) > MAX_APPROVAL_BYTES:
        raise ValueError("operator approval exceeds its signing bound")
    # The child uses the same installed source and interpreter, never a PATH
    # lookup or a mutable user's import path. No wallet constructor is involved.
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
        "runpy.run_module('umi.competition_reward_operator_signing',run_name='__main__')",
        str(Path(__file__).resolve().parents[1]),
        str(path),
        config.series.control_hotkey,
    ]
    with WorkProgress(
        "reward_operator_signing",
        1,
        unit="approvals",
        cohort=body.successor_cohort_sha256,
        estimate=False,
        planning_range_seconds=(0, 90),
        planning_basis="isolated configured signer only; excludes review and reward activation",
    ) as progress:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=os.getgrouplist(account.pw_name, account.pw_gid),
            start_new_session=native_start_new_session(),
        )
        # Reuse the existing bounded duplex collector, including its timeout
        # kill/reap cleanup. SDK diagnostics never enter the parent process.
        output = _communicate_bounded(
            process, raw, maximum_response_bytes=MAX_APPROVAL_BYTES, timeout_seconds=90
        )
        if process.returncode or len(output) > MAX_APPROVAL_BYTES:
            raise ValueError("configured operator signer refused the exact approval")
        signed = SignedRewardTransitionApproval.model_validate_json(output)
        if signed.approval != body or canonical_json_bytes(signed) != output:
            raise ValueError("operator signer returned a different exact approval")
        progress.advance()
    # The existing root publisher performs native signature/authority validation
    # before the immutable publication. Do not repeat it here.
    return signed


def main():
    if len(sys.argv) != 3 or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("isolated named operator signer required")
    raw = sys.stdin.buffer.read(MAX_APPROVAL_BYTES + 1)
    if len(raw) > MAX_APPROVAL_BYTES:
        raise ValueError("operator approval exceeds its signing bound")
    body = RewardTransitionApproval.model_validate_json(raw)
    if canonical_json_bytes(body) != raw:
        raise ValueError("operator approval must retain exact canonical bytes")
    key = load_named_hotkey(Path(sys.argv[1]), sys.argv[2])
    signed = SignedRewardTransitionApproval(approval=body, signature=sign_object(body, key))
    output = canonical_json_bytes(signed)
    if len(output) > MAX_APPROVAL_BYTES:
        raise ValueError("signed operator approval exceeds its publication bound")
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Do not forward key loader/SDK diagnostics into operator logs.
        print("operator signer refused: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
