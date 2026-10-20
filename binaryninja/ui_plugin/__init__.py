"""Binary Ninja UI commands for the repository's annotation format."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from binaryninja.interaction import get_open_filename_input, get_save_filename_input

from binaryninja import PluginCommand, log_error, log_info

CORE_PATH = Path(__file__).resolve().parents[1] / "annotations.py"
SPEC = importlib.util.spec_from_file_location("promon_annotation_core", CORE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load annotation core: {CORE_PATH}")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)


def apply_annotations(view) -> None:
    selected = get_open_filename_input("Select annotations JSON", "*.json")
    if not selected:
        return
    try:
        document = CORE.load_spec(Path(selected))
        CORE.apply_to_view(view, document)
        view.update_analysis_and_wait()
        log_info(f"Applied annotations from {selected}; save the database to keep them")
    except Exception as error:  # noqa: BLE001 - do not unwind through the UI
        log_error(f"Could not apply annotations: {error}")


def export_annotations(view) -> None:
    selected = get_save_filename_input("Export annotations JSON", "*.json")
    if not selected:
        return
    try:
        CORE.export_view(view, Path(selected))
        log_info(f"Exported annotations to {selected}")
    except Exception as error:  # noqa: BLE001 - do not unwind through the UI
        log_error(f"Could not export annotations: {error}")


PluginCommand.register(
    "Promon Research\\Apply annotations JSON",
    "Apply function names, prototypes, types, symbols, and comments",
    apply_annotations,
)
PluginCommand.register(
    "Promon Research\\Export annotations JSON",
    "Export user function names, prototypes, and comments",
    export_annotations,
)
