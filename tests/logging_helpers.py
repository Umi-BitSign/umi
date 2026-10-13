"""Read the emitted telemetry text, including production redaction formatting."""

import ast


def progress_payloads(records, *, logger, event):
    prefix = event + " "
    return [
        ast.literal_eval(record.getMessage().removeprefix(prefix))
        for record in records
        if record.name == logger and record.getMessage().startswith(prefix)
    ]
