from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_c5_guide_uses_a_complete_fresh_protocol_namespace() -> None:
    guide = (ROOT / "docs/miners/connection.md").read_text()
    model = (ROOT / "docs/miners/model.md").read_text()

    for state in (
        "--nonce-db /ABSOLUTE/NEW/C5/protocol/nonces.sqlite3",
        "--assignment-db /ABSOLUTE/NEW/C5/protocol/assignments.sqlite3",
        "--finality-state /ABSOLUTE/NEW/C5/protocol/finality.sqlite3",
    ):
        assert state in guide
    assert "Keep the existing nonce database" not in guide
    assert "Keep the existing nonce database" not in model
    assert "do not give it to the C5 process" in guide
    assert "A transport-policy change gets a fresh private state namespace" in model
