"""Retained launchers must parse native requests before any model-store effect."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("launcher", ["canonical", "retained_runpy"])
def test_isolated_initializer_launcher_resolves_schemas_before_native_effect(tmp_path, launcher):
    source = Path(__file__).resolve().parents[1] / "src"
    request = {
        "schema": "umi-model-generation-owner-initialize/1",
        "store": {
            "schema": "umi-model-byte-verification-store/1",
            "directory": str(tmp_path / "must-not-exist"),
            "imports": [],
            "generation_owner": {
                "schema": "umi-model-generation-owner/1",
                "owner_sha256": "a" * 64,
                "namespace_sha256": "b" * 64,
                "retention": "retain_original_generations_until_authenticated_release",
                "maximum_bytes": 268435456,
            },
        },
    }
    launch = (
        "from umi.competition_model_byte_store_cli import main;raise SystemExit(main())"
        if launcher == "canonical"
        else (
            "import runpy;"
            "runpy.run_module('umi.competition_model_byte_store_cli',run_name='__main__')"
        )
    )
    code = f"""
import sys,json
sys.path.insert(0,{str(source)!r})
from umi import competition_host_activation as control
from umi import competition_model_generation_store as generation
from umi.protocol import canonical_json_bytes
request={request!r}
reads=[]
def read(path, maximum, *, modes):
 assert path.name == 'request.json' and modes == {{0o444}}
 reads.append(str(path))
 return canonical_json_bytes(request)
control._read_root_control_path=read
class Validated(BaseException): pass
def sentinel(directory, owner, *, semantics):
 assert str(directory) == request['store']['directory']
 assert owner.model_dump(mode='json',by_alias=True) == request['store']['generation_owner']
 assert len(semantics) == 2 and len(reads) == 1
 raise Validated
generation.initialize_generation_owner=sentinel
def audit(event,args):
 if event == 'sqlite3.connect' or event.startswith('socket.'):
  raise AssertionError('launcher validation forbids databases/network')
sys.addaudithook(audit)
try: exec({launch!r})
except Validated: print(json.dumps(dict(native_request_validated=True,initialized_owners=0)))
else: raise AssertionError('native initialization sentinel was not reached')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            code,
            "initialize-generations",
            "--request",
            "request.json",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert json.loads(result.stdout) == {"native_request_validated": True, "initialized_owners": 0}
    assert not (tmp_path / "must-not-exist").exists()
