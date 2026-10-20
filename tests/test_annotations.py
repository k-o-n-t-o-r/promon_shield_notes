from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "binaryninja" / "annotations.py"
)
SPEC = importlib.util.spec_from_file_location("annotation_helpers", MODULE_PATH)
assert SPEC and SPEC.loader
annotations = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(annotations)


class AnnotationSchemaTests(unittest.TestCase):
    def test_minimal_spec(self) -> None:
        spec = annotations.validate_spec(
            {
                "format": 1,
                "slide": "0x400000",
                "functions": [
                    {"address": "0x1000", "name": "shield_example"}
                ],
            }
        )
        self.assertEqual(spec["slide"], 0x400000)
        self.assertEqual(spec["functions"][0]["name"], "shield_example")

    def test_missing_function_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "name"):
            annotations.validate_spec(
                {
                    "format": 1,
                    "functions": [{"address": "0x1000"}],
                }
            )

    def test_export_document_contains_user_annotations_only(self) -> None:
        class Symbol:
            def __init__(self, auto: bool) -> None:
                self.auto = auto

        class Function:
            def __init__(self, address: int, name: str, auto: bool) -> None:
                self.start = address
                self.name = name
                self.symbol = Symbol(auto)
                self.type = "int32_t()"
                self.comments = {address: f"{name} comment"}

        class View:
            def __init__(self) -> None:
                self.functions = [
                    Function(0x1000, "user_name", False),
                    Function(0x2000, "auto_name", True),
                ]
                self.address_comments = {0x3000: "data comment"}

        document = annotations.annotation_document(View())
        self.assertEqual(
            [item["name"] for item in document["functions"]],
            ["user_name"],
        )
        self.assertEqual(document["comments"][0]["address"], "0x1000")
        self.assertEqual(document["global_comments"][0]["address"], "0x3000")


if __name__ == "__main__":
    unittest.main()
