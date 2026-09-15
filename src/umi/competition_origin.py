"""Read-only, owned-finality Axon checks for successor endpoint dispatch.

The result proves registration and the announced IP/port at a pinned state root.
For signed hostnames, a separate local DNS observation must include that IP.
It does not prove TLS possession, endpoint availability or publication timing.
The endpoint transport pins that IP and authenticates TLS and the miner response.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import FinalizedRegistrationProvider, _AwaitingFinality, _hotkey, _uint
from .encoding import account_id32
from .grandpa_finality_supervisor import GrandpaFinalitySupervisorError
from .open_competition import SignedSubmission, digest
from .protocol import canonical_json_bytes
from .validator import OriginResolver, _system_origin_resolver
from .validator_chain import PinnedRuntimeContext, StorageReadSpec, ValidatorChainError

_MAX_ORIGIN_EVIDENCE_BYTES = 32 * 1024**2
_MAX_DNS_ADDRESSES = 64


def public_ip_origin(value: str) -> str:
    """Accept only a canonical public literal-IP HTTPS origin, without DNS."""
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise ValueError("endpoint needs a public literal-IP HTTPS origin")
    address = ipaddress.ip_address(parsed.hostname)
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or getattr(address, "ipv4_mapped", None) is not None
        or getattr(address, "sixtofour", None) is not None
        or getattr(address, "teredo", None) is not None
        or "%" in parsed.hostname
    ):
        raise ValueError("endpoint IP is not an ordinary globally routed address")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port is invalid")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    canonical = f"https://{host}:{port}"
    permitted = {canonical, canonical + "/"}
    if port == 443:
        permitted.update({f"https://{host}", f"https://{host}/"})
    if value not in permitted:
        raise ValueError("endpoint origin is not canonical")
    return canonical


def public_https_origin(value: str) -> str:
    """Canonicalize an IP or DNS HTTPS origin; DNS still needs a public-IP check."""
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise ValueError("endpoint needs a public HTTPS origin")
    hostname = parsed.hostname
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return public_ip_origin(value)
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) for s in labels)
        or not re.fullmatch(r"[a-z][a-z0-9-]*", labels[-1])
        or hostname.endswith((".local", ".localhost", ".internal", ".onion", ".home.arpa"))
    ):
        raise ValueError("endpoint hostname must be a canonical public DNS name")
    try:
        if hostname.encode("ascii").decode("idna").encode("idna").decode("ascii") != hostname:
            raise ValueError("noncanonical IDNA hostname")
    except UnicodeError as error:
        raise ValueError("invalid IDNA hostname") from error
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port is invalid")
    canonical = f"https://{hostname}:{port}"
    permitted = {canonical, canonical + "/"}
    if port == 443:
        permitted.update({f"https://{hostname}", f"https://{hostname}/"})
    if value not in permitted:
        raise ValueError("endpoint origin is not canonical")
    return canonical


def _axon_origin(value, *, block: int) -> str:
    bounds = {
        "block": 2**64 - 1,
        "version": 2**32 - 1,
        "ip": 2**128 - 1,
        "port": 65535,
        "ip_type": 255,
        "protocol": 255,
        "placeholder1": 255,
        "placeholder2": 255,
    }
    if not isinstance(value, dict) or set(value) != set(bounds):
        raise ValueError("announced Axon has an unsupported shape")
    for name, maximum in bounds.items():
        _uint(value[name], maximum)
    # The current SDK's ServeAxon intent defaults to application tag 4;
    # existing miners use tag 0. Neither tag replaces HTTPS/TLS verification.
    if not 0 < value["block"] <= block or value["protocol"] not in {0, 4}:
        raise ValueError("announced Axon is unserved, future-dated or has an unsupported tag")
    address = ipaddress.ip_address(value["ip"])
    if address.version != value["ip_type"]:
        raise ValueError("announced Axon IP version mismatch")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return public_ip_origin(f"https://{host}:{value['port']}")


@dataclass(frozen=True, slots=True)
class EndpointOriginCapture:
    submission_sha256: str
    uid: int
    hotkey: str
    origin: str
    block: int
    block_hash: str
    state_root: str
    timestamp_ms: int
    evidence: bytes
    connection_origin: str | None = None

    def transport_resolver(self) -> OriginResolver | None:
        """Use the captured chain IP, retaining the signed hostname for TLS/SNI."""
        origin = public_https_origin(self.origin)
        connection = public_ip_origin(self.connection_origin or self.origin)
        if origin == connection:
            return None  # Literal IP: the existing transport needs no DNS binding.
        parsed, pinned = urlsplit(origin), urlsplit(connection)
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise ValueError("literal endpoint connection binding mismatch")
        if parsed.port != pinned.port:
            raise ValueError("endpoint connection port mismatch")

        async def resolve(hostname: str, port: int):
            if hostname != parsed.hostname or port != parsed.port:
                raise ValueError("endpoint resolver binding mismatch")
            return (pinned.hostname,)

        return resolve

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.evidence).hexdigest()

    def status(self) -> dict:
        return {
            "schema": "umi-competition-endpoint-origin-status/1"
            if self.connection_origin is None
            else "umi-competition-endpoint-origin-status/2",
            "submission_sha256": self.submission_sha256,
            "uid": self.uid,
            "hotkey": self.hotkey,
            "origin": self.origin,
            "block": self.block,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "evidence_sha256": self.evidence_sha256,
            "evidence_class": "verifier_attested_finality",
            "offline_finality_proof": False,
            "tls_verified": False,
            "publication_timing_proven": False,
            "chain_submission_authorized": False,
            **(
                {}
                if self.connection_origin is None
                else {"connection_origin": self.connection_origin, "dns_is_chain_proven": False}
            ),
        }


class FinalizedEndpointProvider(FinalizedRegistrationProvider):
    """Reuse the owned sidecar/runtime verifier; retain origin evidence privately.

    Use a dedicated state directory. No config option accepts an injected proof
    source; inherited port injections exist only for in-process tests.
    """

    def __init__(self, config, policy, *, resolver: OriginResolver | None = None, **test_ports):
        if resolver is not None and test_ports.get("finality") is None:
            raise ValueError("resolver injection requires in-process test ports")
        super().__init__(config, policy, **test_ports)
        self._resolver = resolver or _system_origin_resolver

    async def _bind_origin(self, origin: str, announced: str) -> dict | None:
        if origin == announced:
            return None
        parsed, axon = urlsplit(origin), urlsplit(announced)
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise ValueError("submitted endpoint differs from finalized Axon")
        if parsed.port != axon.port:
            raise ValueError("submitted endpoint port differs from finalized Axon")
        answers = await self._resolver(parsed.hostname, parsed.port)
        if not isinstance(answers, (list, tuple)) or not 0 < len(answers) <= _MAX_DNS_ADDRESSES:
            raise ValueError("endpoint DNS response must be nonempty and bounded")
        addresses = set()
        for value in answers:
            if not isinstance(value, str):
                raise ValueError("endpoint DNS response contains an invalid IP")
            address = ipaddress.ip_address(value)
            host = f"[{address.compressed}]" if address.version == 6 else address.compressed
            # Reject every unsafe answer, even if another answer matches the Axon.
            public_ip_origin(f"https://{host}:{axon.port}")
            addresses.add(address.compressed)
        if axon.hostname not in addresses:
            raise ValueError("endpoint DNS does not include the finalized Axon IP")
        return {
            "hostname": parsed.hostname,
            "addresses": sorted(addresses),
            "observed_at_unix_ms": self._now_ms(),
            "evidence_class": "local_resolver_observation",
            "chain_storage_proven": False,
        }

    def _connect(self):
        directory = self._path.parent.stat()
        if directory.st_uid != os.getuid() or directory.st_mode & 0o077:
            raise ValueError("endpoint cache directory must be owned and private")
        for path in (
            self._path,
            self._path.with_name(self._path.name + "-wal"),
            self._path.with_name(self._path.name + "-shm"),
            self._path.with_name(self._path.name + "-journal"),
        ):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("endpoint cache files must be owned private regular files")
        descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        return super()._connect()

    def _initialize_cache(self) -> None:
        super()._initialize_cache()
        connection = self._connect()
        try:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS origins (
                    block INTEGER NOT NULL, hash TEXT NOT NULL,
                    submission TEXT NOT NULL, evidence BLOB NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    PRIMARY KEY (block, submission)
                )
            """)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(origins)")}
            if columns != {"block", "hash", "submission", "evidence", "evidence_sha256"}:
                raise ValueError(
                    "unsupported endpoint cache schema; retain it for explicit migration"
                )
        finally:
            connection.close()

    async def collect(self):
        raise ValueError("endpoint provider requires an explicit signed submission")

    async def wait_origin_ready(self, signed: SignedSubmission) -> EndpointOriginCapture:
        async def ready():
            while True:
                if self._owned and self._task is not None and self._task.done():
                    self._task.result()
                try:
                    return await self.collect_origin(signed)
                except _AwaitingFinality:
                    pass
                except ValidatorChainError as error:
                    if not (
                        error.reason_code == "owned_finality_unavailable"
                        and type(error.__cause__) is GrandpaFinalitySupervisorError
                        and error.__cause__.reason_code == "no_verified_finalized_head"
                    ):
                        raise
                await asyncio.sleep(0.25)

        try:
            return await asyncio.wait_for(ready(), timeout=self.config.startup_timeout_seconds)
        except asyncio.TimeoutError as error:
            raise ValueError("endpoint origin startup timed out") from error

    async def collect_origin(self, signed: SignedSubmission) -> EndpointOriginCapture:
        if self._closed:
            raise ValueError("endpoint provider is closed")
        signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
        sub = signed.submission
        if (
            sub.track != "endpoint"
            or sub.policy_sha256 != digest(self.policy)
            or sub.accepted_terms_sha256 != self.policy.contribution_terms_sha256
            or sub.valid_through_block - sub.valid_from_block
            > self.policy.maximum_submission_lifetime_blocks
            or not self.policy.valid_from_block
            <= sub.valid_from_block
            < sub.valid_through_block
            <= self.policy.valid_through_block
        ):
            raise ValueError("endpoint submission policy/terms/lifetime mismatch")
        origin = public_https_origin(sub.endpoint_url)
        try:
            return await asyncio.wait_for(
                self._collect_origin_locked(signed, origin),
                timeout=self.config.collection_timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise ValueError("endpoint origin proof collection timed out") from error

    async def _collect_origin_locked(self, signed, origin) -> EndpointOriginCapture:
        async with self._lock:
            if self._owned and (self._task is None or self._task.done()):
                raise ValueError("owned finality observer is not running")
            ref = await self._proofs.finalized_snapshot()
            if not isinstance(ref, FinalizedSnapshotRef):
                raise ValueError("endpoint finalized snapshot is invalid")
            if ref.block_number < self.config.minimum_finalized_block or (
                self._owned and ref.block_number <= self._startup_floor
            ):
                raise _AwaitingFinality("awaiting a head verified by this observer process")
            sub = signed.submission
            if not sub.valid_from_block <= ref.block_number <= sub.valid_through_block:
                raise ValueError("endpoint submission is not current")
            block = await self._finality.verified_block_at(ref.block_number)
            self._check_finality(ref, block)
            self._fresh(block.timestamp_ms)
            self._check_origin_prior(ref)
            runtime = await self._proofs.pinned_runtime(ref, self._runtime_pin)
            if (
                not isinstance(runtime, PinnedRuntimeContext)
                or runtime.snapshot != ref
                or runtime.pin != self._runtime_pin
            ):
                raise ValueError("endpoint runtime binding mismatch")
            hotkey = _hotkey(sub.hotkey)
            specs = (
                StorageReadSpec("Timestamp", "Now"),
                StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                StorageReadSpec("SubtensorModule", "Uids", (78, hotkey)),
                StorageReadSpec("SubtensorModule", "Axons", (78, hotkey)),
            )
            base = await self._read(runtime, specs)
            values = {read.spec: read.decoded_value for read in base.reads}
            if values[specs[0]] != block.timestamp_ms or type(values[specs[0]]) is not int:
                raise ValueError("endpoint proven timestamp differs from finalized block")
            if values[specs[1]] is not True:
                raise ValueError("endpoint subnet is unavailable")
            uid = _uint(values[specs[2]], self.policy.maximum_uids - 1)
            announced = _axon_origin(values[specs[3]], block=ref.block_number)
            inverse_spec = StorageReadSpec("SubtensorModule", "Keys", (78, uid))
            inverse = await self._read(runtime, (inverse_spec,))
            if account_id32(_hotkey(inverse.reads[0].decoded_value)) != account_id32(hotkey):
                raise ValueError("endpoint UID inverse mapping mismatch")
            dns = await self._bind_origin(origin, announced)
            newest = await self._finality.verified_finalized_snapshot()
            if newest.block_number < ref.block_number or (
                newest.block_number == ref.block_number and newest != ref
            ):
                raise ValueError("endpoint finalized head rolled back or changed")
            if newest.block_number - ref.block_number > self.policy.maximum_snapshot_age_blocks:
                raise ValueError("endpoint snapshot became stale during proof collection")
            evidence = canonical_json_bytes(
                {
                    "schema": "umi-competition-endpoint-origin-evidence/1"
                    if dns is None
                    else "umi-competition-endpoint-origin-evidence/2",
                    **({} if dns is None else {"dns": dns, "connection_origin": announced}),
                    "policy_sha256": digest(self.policy),
                    "signed_submission": signed.model_dump(mode="json"),
                    "uid": uid,
                    "origin": origin,
                    "block": ref.block_number,
                    "block_hash": ref.block_hash,
                    "state_root": ref.state_root,
                    "timestamp_ms": block.timestamp_ms,
                    "finality": json.loads(block.finality_evidence),
                    "finality_verifier_sha256": block.finality_verifier_sha256,
                    "storage_proof_verifier_sha256": self.config.proof_binary_sha256,
                    "runtime_metadata_sha256": runtime.metadata_sha256,
                    "runtime_version": json.loads(runtime.runtime_version_bytes),
                    "storage_batches": [
                        {
                            "state_root": batch.evidence.verified_state_root,
                            "claims": [
                                {
                                    "key": "0x" + claim.storage_key.hex(),
                                    "value": None
                                    if claim.value is None
                                    else "0x" + claim.value.hex(),
                                }
                                for claim in batch.evidence.claims
                            ],
                            "proof": ["0x" + node.hex() for node in batch.evidence.proof],
                        }
                        for batch in (base, inverse)
                    ],
                    "chain_submission_authorized": False,
                }
            )
            if len(evidence) > _MAX_ORIGIN_EVIDENCE_BYTES:
                raise ValueError("endpoint origin evidence exceeds its byte limit")
            capture = EndpointOriginCapture(
                digest(sub),
                uid,
                hotkey,
                origin,
                ref.block_number,
                ref.block_hash,
                ref.state_root,
                block.timestamp_ms,
                evidence,
                None if dns is None else announced,
            )
            return self._save_origin(capture, runtime.metadata_bytes)

    def _check_origin_prior(self, ref):
        connection = self._connect()
        try:
            self._check_origin_highwater(connection, ref.block_number, ref.block_hash)
        finally:
            connection.close()

    @staticmethod
    def _check_origin_highwater(connection, block, block_hash):
        prior = connection.execute(
            "SELECT block, hash FROM origins ORDER BY block DESC LIMIT 1"
        ).fetchone()
        if prior and (block < prior[0] or (block == prior[0] and block_hash != prior[1])):
            raise ValueError("endpoint finalized head rolled back or changed")

    def _save_origin(self, capture, metadata):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._check_origin_highwater(connection, capture.block, capture.block_hash)
            prior = connection.execute(
                "SELECT length(evidence), evidence_sha256 FROM origins "
                "WHERE block=? AND submission=?",
                (capture.block, capture.submission_sha256),
            ).fetchone()
            metadata_id = hashlib.sha256(metadata).hexdigest()
            retained = connection.execute(
                "SELECT body FROM artifacts WHERE digest=?", (metadata_id,)
            ).fetchone()
            if retained and retained[0] != metadata:
                raise ValueError("retained endpoint metadata is corrupt")
            if prior:
                if not 0 < prior[0] <= _MAX_ORIGIN_EVIDENCE_BYTES or retained is None:
                    raise ValueError("retained endpoint evidence or metadata is incomplete")
                prior_bytes = connection.execute(
                    "SELECT evidence FROM origins WHERE block=? AND submission=?",
                    (capture.block, capture.submission_sha256),
                ).fetchone()[0]
                if hashlib.sha256(prior_bytes).hexdigest() != prior[1]:
                    raise ValueError("retained endpoint evidence is corrupt")
                old, new = json.loads(prior_bytes), json.loads(capture.evidence)
                if canonical_json_bytes(old) != prior_bytes:
                    raise ValueError("retained endpoint evidence is noncanonical")
                fields = (
                    "schema",
                    "policy_sha256",
                    "uid",
                    "origin",
                    "block",
                    "block_hash",
                    "state_root",
                    "timestamp_ms",
                    "runtime_metadata_sha256",
                    "storage_proof_verifier_sha256",
                    "finality_verifier_sha256",
                )
                if (
                    any(old[key] != new[key] for key in fields)
                    or old["signed_submission"]["submission"]
                    != new["signed_submission"]["submission"]
                    or old.get("connection_origin") != new.get("connection_origin")
                    or any(
                        old.get("dns", {}).get(key) != new.get("dns", {}).get(key)
                        for key in (
                            "hostname",
                            "addresses",
                            "evidence_class",
                            "chain_storage_proven",
                        )
                    )
                ):
                    raise ValueError("endpoint evidence changed at the same finalized block")
                # Equivalent proof encodings or re-signatures do not replace
                # the first verified evidence retained for this observation.
                capture = replace(capture, evidence=prior_bytes)
            else:
                total = sum(
                    connection.execute(query).fetchone()[0]
                    for query in (
                        "SELECT COALESCE(SUM(length(evidence)), 0) FROM origins",
                        "SELECT COALESCE(SUM(length(evidence)), 0) FROM captures",
                        "SELECT COALESCE(SUM(length(body)), 0) FROM artifacts",
                    )
                )
                added = len(capture.evidence) + (0 if retained else len(metadata))
                if total + added > self.config.maximum_cache_bytes:
                    raise ValueError("endpoint evidence cache is full")
                connection.execute(
                    "INSERT OR IGNORE INTO artifacts VALUES (?, ?)", (metadata_id, metadata)
                )
                connection.execute(
                    "INSERT INTO origins VALUES (?, ?, ?, ?, ?)",
                    (
                        capture.block,
                        capture.block_hash,
                        capture.submission_sha256,
                        capture.evidence,
                        capture.evidence_sha256,
                    ),
                )
            self._fresh(capture.timestamp_ms)
            connection.commit()
            return capture
        finally:
            connection.close()
