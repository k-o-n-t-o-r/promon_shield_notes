#!/usr/bin/env python3
"""Apply or export durable Binary Ninja annotations.

The optional CLI requires an environment with Binary Ninja's headless API.
The UI plugin imports the same helpers inside the licensed GUI. This module
keeps the ``binaryninja`` import inside execution paths so its JSON validation
helpers remain testable with ordinary Python.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


def parse_address(value: Any, field: str = "address") -> int:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value, 0)
    else:
        raise TypeError(f"{field} must be an integer or integer string")
    if result < 0:
        raise ValueError(f"{field} must not be negative")
    return result


def _list_of_objects(spec: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = spec.get(name, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{name} must be a list of objects")
    return value


def validate_spec(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise TypeError("annotation document must be an object")
    if raw.get("format") != 1:
        raise ValueError("unsupported annotation format")
    slide = parse_address(raw.get("slide", 0), "slide")
    types = raw.get("types", [])
    if not isinstance(types, list) or any(
        not isinstance(item, str) or not item.strip() for item in types
    ):
        raise ValueError("types must be a list of nonempty C declarations")

    functions = _list_of_objects(raw, "functions")
    for index, item in enumerate(functions):
        parse_address(item.get("address"), f"functions[{index}].address")
        if not isinstance(item.get("name"), str) or not item["name"]:
            raise ValueError(f"functions[{index}].name must be nonempty")
        if "prototype" in item and not isinstance(item["prototype"], str):
            raise ValueError(f"functions[{index}].prototype must be a string")
        if "comment" in item and not isinstance(item["comment"], str):
            raise ValueError(f"functions[{index}].comment must be a string")

    data_symbols = _list_of_objects(raw, "data_symbols")
    for index, item in enumerate(data_symbols):
        parse_address(item.get("address"), f"data_symbols[{index}].address")
        if not isinstance(item.get("name"), str) or not item["name"]:
            raise ValueError(f"data_symbols[{index}].name must be nonempty")

    comments = _list_of_objects(raw, "comments")
    for index, item in enumerate(comments):
        parse_address(item.get("address"), f"comments[{index}].address")
        if "function" in item:
            parse_address(item["function"], f"comments[{index}].function")
        if not isinstance(item.get("text"), str):
            raise TypeError(f"comments[{index}].text must be a string")

    global_comments = _list_of_objects(raw, "global_comments")
    for index, item in enumerate(global_comments):
        parse_address(item.get("address"), f"global_comments[{index}].address")
        if not isinstance(item.get("text"), str):
            raise TypeError(f"global_comments[{index}].text must be a string")

    return {
        "format": 1,
        "slide": slide,
        "types": types,
        "functions": functions,
        "data_symbols": data_symbols,
        "comments": comments,
        "global_comments": global_comments,
    }


def load_spec(path: Path) -> dict[str, Any]:
    return validate_spec(json.loads(path.read_text()))


def initialize_binary_ninja():
    import binaryninja

    if license_path := os.environ.get("BN_LICENSE_FILE"):
        binaryninja.core_set_license(Path(license_path).read_text())
    return binaryninja


def apply_to_view(view, spec: dict[str, Any]) -> None:
    import binaryninja

    slide = spec["slide"]
    for source in spec["types"]:
        view.define_user_type(None, source)

    for item in spec["functions"]:
        address = parse_address(item["address"]) + slide
        function = view.get_function_at(address)
        if function is None:
            view.create_user_function(address)
            function = view.get_function_at(address)
        if function is None:
            raise ValueError(f"could not create function at 0x{address:x}")
        if item.get("prototype"):
            function.type = item["prototype"]
        function.name = item["name"]
        if item.get("comment"):
            function.set_comment_at(address, item["comment"])

    for item in spec["data_symbols"]:
        address = parse_address(item["address"]) + slide
        view.define_user_symbol(
            binaryninja.Symbol(
                binaryninja.SymbolType.DataSymbol,
                address,
                item["name"],
            )
        )

    for item in spec["comments"]:
        address = parse_address(item["address"]) + slide
        function_address = parse_address(
            item.get("function", item["address"])
        ) + slide
        function = view.get_function_at(function_address)
        if function is None:
            raise ValueError(
                f"no function at 0x{function_address:x} for comment "
                f"at 0x{address:x}"
            )
        function.set_comment_at(address, item["text"])

    for item in spec["global_comments"]:
        view.set_comment_at(
            parse_address(item["address"]) + slide,
            item["text"],
        )


def apply_annotations(binary: Path, spec_path: Path, output: Path) -> None:
    binaryninja = initialize_binary_ninja()
    spec = load_spec(spec_path)
    with binaryninja.load(str(binary)) as view:
        apply_to_view(view, spec)
        view.update_analysis_and_wait()
        output.parent.mkdir(parents=True, exist_ok=True)
        if not view.create_database(str(output)):
            raise RuntimeError(f"failed to create database: {output}")


def annotation_document(view) -> dict[str, Any]:
    functions = []
    comments = []
    for function in view.functions:
        if function.symbol.auto:
            continue
        functions.append(
            {
                "address": f"0x{function.start:x}",
                "name": function.name,
                "prototype": str(function.type),
            }
        )
        comments.extend(
            {
                "function": f"0x{function.start:x}",
                "address": f"0x{address:x}",
                "text": text,
            }
            for address, text in sorted(function.comments.items())
        )

    return {
        "format": 1,
        "slide": "0x0",
        "types": [],
        "functions": sorted(functions, key=lambda item: int(item["address"], 0)),
        "data_symbols": [],
        "comments": comments,
        "global_comments": [
            {"address": f"0x{address:x}", "text": text}
            for address, text in sorted(view.address_comments.items())
        ],
    }


def export_view(view, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(annotation_document(view), indent=2) + "\n")


def export_annotations(binary: Path, output: Path) -> None:
    binaryninja = initialize_binary_ninja()
    with binaryninja.load(str(binary)) as view:
        export_view(view, output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("binary", type=Path)
    apply_parser.add_argument("annotations", type=Path)
    apply_parser.add_argument("--output", required=True, type=Path)

    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("binary", type=Path)
    export_parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "apply":
        apply_annotations(args.binary, args.annotations, args.output)
    else:
        export_annotations(args.binary, args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"ERROR={error}", file=sys.stderr)
        raise SystemExit(1)
