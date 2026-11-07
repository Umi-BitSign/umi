"""Separate preparation owns only its own lifetime and selected resources."""

import shlex

import pytest

from umi.competition_reward_preparation_selection import (
    LegacyPreparationSelection,
    legacy_preparation_selection_sha256,
)
from umi.competition_reward_preparation_service import (
    LegacyPreparationNamespace,
    PreparationMount,
    render_legacy_preparation_service,
)


@pytest.fixture
def selected():
    selection = LegacyPreparationSelection(
        schema="umi-legacy-preparation-selection/1",
        transition_id="01" * 32,
        retained_intent_sha256="02" * 32,
        source_revision="03" * 20,
        config_sha256="04" * 32,
        installation_receipt_sha256="05" * 32,
        standing_boot_sha256="06" * 32,
        provider_directory="/var/lib/umi-preparation/providers",
        maximum_memory_bytes=3 * 1024**3,
        background_cpus=(0, 1, 14, 15),
    )
    namespace = LegacyPreparationNamespace(
        schema="umi-legacy-preparation-namespace/1",
        user="umi-validator",
        group="umi-validator",
        supplementary_groups=("umi-readers",),
        root_directory="/var/lib/umi-installed-root",
        bind_paths=(PreparationMount(source="/var/lib/original-state", target="/state"),),
        bind_read_only_paths=(
            PreparationMount(
                source="/original/maintenance.json",
                target="/etc/umi/validator-supervisor-maintenance.json",
            ),
            PreparationMount(
                source="/original/config.json", target="/etc/umi/validator-supervisor.json"
            ),
            PreparationMount(
                source="/opt/original host", target="/opt/original host", recursive=False
            ),
        ),
        environment={
            "UMI_NATIVE_VERIFICATION_DIRECTORY": "/state/verification",
            "UMI_RPC_TRANSPORT_CONFIG": "/etc/umi/rpc.json",
        },
        tasks_max=1024,
    )
    options = dict(
        unit_name="umi-fixture-preparation.service",
        selection_path="/controls/preparation.json",
        maintenance_path="/controls/new-maintenance.json",
        previous_maintenance_path="/original/maintenance.json",
        provider_host_directory="/var/lib/umi-independent-providers",
    )
    return selection, namespace, options


def test_render_preserves_namespace_selects_signed_command_and_owns_scratch(selected):
    selection, namespace, options = selected
    raw = render_legacy_preparation_service(selection, namespace, **options).decode()
    lines = raw.splitlines()
    for expected in (
        "RootDirectory=/var/lib/umi-installed-root",
        "User=umi-validator",
        "Group=umi-validator",
        "SupplementaryGroups=umi-readers",
        "MemoryMax=3221225472",
        "MemorySwapMax=0",
        "AllowedCPUs=0 1 14 15",
        "TasksMax=1024",
        "RuntimeDirectory=umi-fixture-preparation",
        "RuntimeDirectoryMode=0700",
        "PrivateTmp=yes",
        "SendSIGKILL=no",
        "TimeoutStopSec=infinity",
        "Restart=on-failure",
        "RemainAfterExit=no",
    ):
        assert expected in lines
    assert not any(
        line.startswith(prefix)
        for line in lines
        for prefix in ("ExecStop", "Requires=", "BindsTo=", "PartOf=", "Conflicts=")
    )
    read_only = shlex.split(
        next(line.split("=", 1)[1] for line in lines if line.startswith("BindReadOnlyPaths="))
    )
    assert (
        "/controls/new-maintenance.json:/etc/umi/validator-supervisor-maintenance.json:rbind"
        in read_only
    )
    assert "/original/config.json:/etc/umi/validator-supervisor.json:rbind" in read_only
    assert "/opt/original host:/opt/original host:norbind" in read_only
    writable = shlex.split(
        next(line.split("=", 1)[1] for line in lines if line.startswith("BindPaths="))
    )
    assert writable == [
        "/var/lib/original-state:/state:rbind",
        "/var/lib/umi-independent-providers:/var/lib/umi-preparation/providers:rbind",
    ]
    command = shlex.split(
        next(line.split("=", 1)[1] for line in lines if line.startswith("ExecStart="))
    )
    source = "/opt/umi-validator-supervisor-hosts/" + selection.source_revision
    assert command[:4] == [
        source + "/.venv/bin/python",
        "-I",
        "-B",
        source + "/.venv/bin/umi-competition-supervisor",
    ]
    assert command[-2:] == [
        "--legacy-preparation-selection-sha256",
        legacy_preparation_selection_sha256(selection),
    ]
    assert render_legacy_preparation_service(selection, namespace, **options).decode() == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("unit_name", "umi-validator@54.service"),
        ("unit_name", "umi-x-preparation.service\nExecStart=/bad"),
        ("selection_path", "/controls/%i.json"),
        ("selection_path", "/controls/$NAME.json"),
        ("selection_path", "/controls/a\nExecStart=/bad"),
        ("selection_path", "/controls/../bad"),
        ("maintenance_path", "/controls/a:b"),
        ("previous_maintenance_path", "/other/maintenance.json"),
        ("provider_host_directory", "/var/lib/original-state/child"),
        ("provider_host_directory", "/var/lib"),
        ("provider_host_directory", "/var/lib/umi-installed-root/child"),
        ("selection_path", "/var/lib/umi-preparation/providers/control.json"),
    ],
)
def test_refuse_injection_and_shared_storage_before_unit_publication(selected, field, value):
    selection, namespace, options = selected
    with pytest.raises(ValueError):
        render_legacy_preparation_service(selection, namespace, **{**options, field: value})


@pytest.mark.parametrize(
    "change", ["root", "environment", "duplicate_mount", "construct_bypass", "selected_source"]
)
def test_namespace_refuses_unsupported_or_mutated_selection(selected, change):
    selection, namespace, options = selected
    raw = namespace.model_dump(by_alias=True)
    if change == "root":
        raw["user"] = "root"
    elif change == "environment":
        raw["environment"]["LD_PRELOAD"] = "/unselected/library"
    elif change == "duplicate_mount":
        raw["bind_read_only_paths"] += (raw["bind_read_only_paths"][0],)
    elif change == "construct_bypass":
        # Revalidation at rendering rejects a model-copy bypass of validation.
        namespace = namespace.model_copy(update={"user": "root\nExecStart=/bad"})
    else:
        raw["bind_read_only_paths"] += (
            {
                "source": "/other/source",
                "target": "/opt/umi-validator-supervisor-hosts/" + selection.source_revision,
                "recursive": True,
            },
        )
    with pytest.raises(ValueError):
        if change != "construct_bypass":
            namespace = LegacyPreparationNamespace.model_validate(raw)
        render_legacy_preparation_service(selection, namespace, **options)


def test_installed_unlimited_task_count_is_preserved_under_selected_memory_cap(selected):
    selection, namespace, options = selected
    namespace = namespace.model_copy(update={"tasks_max": "infinity"})
    body = render_legacy_preparation_service(selection, namespace, **options).decode()
    assert "TasksMax=infinity\n" in body
    assert "MemoryMax=3221225472\n" in body
    with pytest.raises(ValueError):
        render_legacy_preparation_service(
            selection,
            namespace.model_copy(update={"tasks_max": "infinity\nMemoryMax=infinity"}),
            **options,
        )
