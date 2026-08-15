from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from security_agent.application.settings import (
    LLMSettings,
    ProductSettings,
    SettingsError,
    load_product_settings,
)


class ProductSettingsTests(unittest.TestCase):
    def test_missing_file_disables_llm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = load_product_settings(Path(directory) / "missing.json")

        self.assertEqual(ProductSettings(), settings)
        self.assertFalse(settings.llm.enabled)

    def test_loads_enabled_openai_compatible_settings_with_utf8_bom(self) -> None:
        document = {
            "llm": {
                "enabled": True,
                "provider": "openai-compatible",
                "base_url": "https://models.example/v1",
                "api_key": "top-secret",
                "model": "example-model",
                "timeout_seconds": 12.5,
                "max_response_bytes": 4096,
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps(document), encoding="utf-8-sig")

            settings = load_product_settings(path)

        self.assertEqual("https://models.example/v1", settings.llm.base_url)
        self.assertEqual("top-secret", settings.llm.api_key)
        self.assertEqual(12.5, settings.llm.timeout_seconds)
        self.assertEqual(4096, settings.llm.max_response_bytes)
        self.assertNotIn("top-secret", repr(settings))

    def test_empty_object_uses_disabled_defaults(self) -> None:
        settings = self._load("{}")

        self.assertEqual(ProductSettings(), settings)

    def test_rejects_unknown_and_duplicate_keys(self) -> None:
        invalid_documents = (
            '{"other": {}}',
            '{"llm": {"enabled": false, "other": true}}',
            '{"llm": {}, "llm": {}}',
            '{"llm": {"enabled": false, "enabled": true}}',
        )

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(SettingsError):
                self._load(document)

    def test_rejects_non_objects_and_wrong_field_types(self) -> None:
        invalid_documents = (
            "[]",
            '{"llm": null}',
            '{"llm": {"enabled": 1}}',
            '{"llm": {"provider": false}}',
            '{"llm": {"timeout_seconds": true}}',
            '{"llm": {"timeout_seconds": "60"}}',
            '{"llm": {"max_response_bytes": 1.5}}',
        )

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(SettingsError):
                self._load(document)

    def test_enabled_llm_requires_supported_provider_and_non_empty_fields(self) -> None:
        base = {
            "enabled": True,
            "provider": "openai-compatible",
            "base_url": "https://models.example/v1",
            "api_key": "top-secret",
            "model": "example-model",
        }
        invalid = (
            {**base, "provider": "other"},
            {**base, "base_url": " "},
            {**base, "api_key": " "},
            {**base, "model": " "},
        )

        for llm in invalid:
            with self.subTest(llm=llm), self.assertRaises(SettingsError) as caught:
                self._load(json.dumps({"llm": llm}))
            self.assertNotIn("top-secret", str(caught.exception))

    def test_rejects_invalid_numbers_without_exposing_api_key(self) -> None:
        for value in ("0", "-1", "NaN", "Infinity"):
            document = '{"llm":{"api_key":"top-secret","timeout_seconds":' + value + "}}"
            with self.subTest(value=value), self.assertRaises(SettingsError) as caught:
                self._load(document)
            self.assertNotIn("top-secret", str(caught.exception))

        with self.assertRaises(SettingsError):
            self._load('{"llm":{"max_response_bytes":0}}')

    def test_rejects_oversized_and_non_utf8_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b" " * (64 * 1024 + 1))
            with self.assertRaises(SettingsError):
                load_product_settings(oversized)

            non_utf8 = Path(directory) / "non-utf8.json"
            non_utf8.write_bytes(b"{\xff}")
            with self.assertRaises(SettingsError):
                load_product_settings(non_utf8)

    def test_api_key_is_hidden_from_direct_llm_settings_repr(self) -> None:
        settings = LLMSettings(api_key="top-secret")

        self.assertNotIn("top-secret", repr(settings))

    @staticmethod
    def _load(document: str) -> ProductSettings:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(document, encoding="utf-8")
            return load_product_settings(path)


if __name__ == "__main__":
    unittest.main()
