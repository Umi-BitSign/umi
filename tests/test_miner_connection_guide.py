from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_c5_guide_uses_one_reusable_policy_bound_updater() -> None:
    guide = (ROOT / "docs/miners/connection.md").read_text()
    model = (ROOT / "docs/miners/model.md").read_text()

    assert "upgrade.py --public-model-track no" in guide
    assert "same file for C6 and later cohorts" in guide
    assert "No cohort-specific replacement script is needed" in guide.replace("\n", " ")
    assert "Nonce, assignment,\nfinality, grant and model-sidecar state" in guide
    assert "Keep the existing nonce database" not in guide
    assert "Keep the existing nonce database" not in model
    assert "A transport-policy change gets a fresh private state namespace" in model
