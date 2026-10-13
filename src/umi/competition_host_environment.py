"""Versioned clean-environment contract for successor host service rendering.

Presence in the authenticated target host manifest selects this rendering.
Older manifests retain their original bytes for interrupted recovery and drain.
Keep this module stable while either layout is a supported migration source.
"""

NATIVE_VERIFICATION_ASSIGNMENT = (
    "UMI_NATIVE_VERIFICATION_DIRECTORY=${UMI_NATIVE_VERIFICATION_DIRECTORY}"
)
