"""Read the emitted telemetry text, including production redaction formatting."""

import ast
import json


def progress_payloads(records, *, logger, event):
    prefix = event + " "
    return [
        ast.literal_eval(record.getMessage().removeprefix(prefix))
        for record in records
        if record.name == logger and record.getMessage().startswith(prefix)
    ]


def json_progress_payloads(records, *, logger, schema):
    """Select emitted JSON events without treating other logger formats as JSON.

    A malformed JSON-framed event still fails the test; unrelated text events
    are valid peers on the shared progress logger. Parse each selected line once.
    """
    result = []
    for record in records:
        if record.name != logger:
            continue
        message = record.getMessage()
        if not message.lstrip().startswith("{"):
            continue
        event = json.loads(message)
        if event.get("schema") == schema:
            result.append(event)
    return result
