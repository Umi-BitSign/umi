"""Select an offline entrypoint from the unchanged signed model manifest.

The reference wrapper has a canonical root name. Routed models may declare
additional inference helpers; they are authenticated payload, not alternative
programs for the evaluator to choose based on a challenge or its output.
"""

from .open_competition import ModelBundle


def model_python_entrypoint(bundle: ModelBundle) -> str:
    entries = tuple(file.path for file in bundle.files if file.role == "inference")
    if len(entries) == 1 and entries[0].endswith(".py"):
        return entries[0]
    if "umi_inference.py" in entries:
        return "umi_inference.py"
    raise ValueError(
        "model requires one declared Python inference entrypoint, or a root "
        "umi_inference.py declared as inference when helpers share that role"
    )
