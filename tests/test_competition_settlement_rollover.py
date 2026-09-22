"""One retained delivery journal follows independent, fully replayed rounds."""

from pathlib import Path

import pytest

from umi import competition_settlement_delivery as delivery
from umi.competition_package import PreparedCompetitionPackage, load_competition_package
from umi.competition_publication import settlement_publication_digest
from umi.competition_rounds import SettlementDeliveryConfig
from umi.competition_settlement_preparation import SettlementPreparation
from umi.competition_settlement_signing import SettlementEndorsement
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_rounds import OwnedProvider
from .test_competition_successor_publication import next_package as next_package
from .test_competition_successor_publication import package_case as package_case
from .test_competition_successor_publication import package_limits as package_limits
from .test_competition_successor_publication import policy as policy
from .test_competition_successor_publication import release_identity as release_identity
from .test_competition_successor_publication import replay_limits as replay_limits


@pytest.mark.asyncio
async def test_second_round_recovers_partial_delivery_without_changing_first_package(
    package_case,
    policy,
    package_limits,
    release_identity,
    replay_limits,
    tmp_path,
    request,
    monkeypatch,
):
    config = SettlementDeliveryConfig(
        state_directory=str(tmp_path / "delivery-state"),
        certificate_directory=str(tmp_path / "delivered"),
        package_directory=str(tmp_path / "delivery-packages"),
        package_limits=package_limits,
        release_identity=release_identity,
    )
    provider = OwnedProvider(160)

    def reopen():
        return delivery.SettlementQueue(
            config,
            package_case.scenario.store,
            provider,
            limits=replay_limits,
            maximum_rounds=16,
            maximum_bytes=16 * 1024**2,
        )

    def load(prepared):
        return load_competition_package(
            Path(prepared.package_path),
            expected_package_sha256=prepared.package_sha256,
            expected_policy_sha256=prepared.policy_sha256,
            observed_release=release_identity,
            limits=package_limits,
        )

    original_publish = delivery._publish
    first_bytes = None
    try:
        queue = reopen()
        for sequence in (1, 2):
            # Construct the second real settlement only after delivering the
            # first. The same intake retains its promotion and round history.
            case = package_case if sequence == 1 else request.getfixturevalue("next_package")
            package = load(case.prepared)
            prepared = SettlementPreparation(
                schema="umi-settlement-preparation/1",
                cutoff=package.cutoff_certificate,
                publication=package.settlement_certificate.publication,
                roster=package.roster,
                evidence=package.evidence,
            )
            provider.block = package.retained_settlement.observed_block
            queue = reopen()
            assert await queue.prepare(prepared) is None
            publication = settlement_publication_digest(prepared.publication)
            votes = tuple(
                SettlementEndorsement(publication_sha256=publication, signature=signature)
                for signature in package.settlement_certificate.signatures
            )
            cursor, pending = await queue.pending(votes[0].signature.hotkey)
            assert cursor == sequence and pending == (prepared,)
            await queue.accept(votes[0])
            if sequence == 2:

                def interrupted(path, value):
                    if str(path).endswith(".package.json"):
                        raise OSError("synthetic descriptor publication failure")
                    return original_publish(path, value)

                monkeypatch.setattr(delivery, "_publish", interrupted)
                with pytest.raises(OSError, match="descriptor publication failure"):
                    await queue.accept(votes[-1])
                retained = canonical_json_bytes(queue.journal.get("certificate", "2"))
                monkeypatch.setattr(delivery, "_publish", original_publish)
                queue = reopen()
            await queue.accept(votes[-1])
            descriptor = Path(config.certificate_directory) / (publication + ".package.json")
            delivered = read_private_model(descriptor, PreparedCompetitionPackage)
            verified = load(delivered)
            assert verified.retained_settlement == package.retained_settlement
            assert verified.manifest.round_sequence == sequence
            if sequence == 1:
                first_bytes = canonical_json_bytes(verified)
                first_descriptor = descriptor
            else:
                assert canonical_json_bytes(queue.journal.get("certificate", "2")) == retained
                assert (
                    canonical_json_bytes(
                        load(read_private_model(first_descriptor, PreparedCompetitionPackage))
                    )
                    == first_bytes
                )
        assert queue.journal.keys("package") == ["1", "2"]
        assert len(list(Path(config.certificate_directory).glob("*.package.json"))) == 2
    finally:
        for path in Path(config.package_directory).iterdir():
            if path.is_dir():
                path.chmod(0o700)
