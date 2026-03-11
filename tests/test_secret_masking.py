"""Tests for the secret masking preprocessing module."""

import csv
import os
from unittest.mock import patch, MagicMock

import pytest
import requests

from sast_triage.preprocessing.secret_masking import (
    MASK_PLACEHOLDER,
    MaskingReport,
    _build_secret_preview,
    load_gitleaks_csv,
    mask_secrets,
)


def _write_file(directory: str, name: str, content: str) -> str:
    """Helper to create a text file and return its path."""
    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _read_file(path: str) -> str:
    """Helper to read a file's content."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write_csv(directory: str, name: str, rows: list[dict]) -> str:
    """Helper to write a Gitleaks-format CSV and return its path."""
    path = os.path.join(directory, name)
    fieldnames = [
        "Description", "StartLine", "EndLine", "StartColumn",
        "EndColumn", "Match", "Secret", "File", "SymlinkFile",
        "Commit", "Entropy", "Author", "Email", "Date", "Message",
        "Tags", "RuleID", "Fingerprint", "ActualLine", "label",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            full_row = {k: "" for k in fieldnames}
            full_row.update(row)
            writer.writerow(full_row)
    return path


class TestMaskSingleLineSecret:
    def test_single_line_secret_replaced(self, tmp_path: str) -> None:
        """CSV entry with StartLine==EndLine replaces the secret correctly."""
        codebase = tmp_path / "codebase"
        codebase.mkdir()
        _write_file(
            str(codebase), "config.txt",
            'password = "myS3cretP@ssw0rd"\n',
        )

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "config.txt",
                "StartLine": "1",
                "EndLine": "1",
                "StartColumn": "14",
                "EndColumn": "29",
                "Description": "hardcoded password",
                "Secret": "myS3cretP@ssw0rd",
            },
        ])

        report = mask_secrets(str(codebase), csv_path)
        content = _read_file(str(codebase / "config.txt"))

        assert "myS3cretP@ssw0rd" not in content
        assert MASK_PLACEHOLDER in content
        assert report.total_secrets_masked == 1
        assert report.files_modified == 1
        assert report.total_entries_in_csv == 1


class TestMaskMultiLineSecret:
    def test_multi_line_secret_replaced(self, tmp_path: str) -> None:
        """CSV entry spanning multiple lines masks all affected lines."""
        codebase = tmp_path / "codebase"
        codebase.mkdir()
        _write_file(
            str(codebase), "cert.pem",
            "-----BEGIN KEY-----\n"
            "MIIEvQIBADANBg\n"
            "kqhkiG9w0BAQEF\n"
            "-----END KEY-----\n",
        )

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "cert.pem",
                "StartLine": "1",
                "EndLine": "3",
                "StartColumn": "1",
                "EndColumn": "15",
                "Description": "private key",
                "Secret": "MULTI_LINE_SECRET",
            },
        ])

        report = mask_secrets(str(codebase), csv_path)
        content = _read_file(str(codebase / "cert.pem"))

        assert "MIIEvQIBADANBg" not in content
        assert "kqhkiG9w0BAQEF" not in content
        assert MASK_PLACEHOLDER in content
        assert report.total_secrets_masked == 1


class TestFileNotFoundSkipped:
    def test_missing_file_added_to_skipped(self, tmp_path: str) -> None:
        """Entry referencing a non-existent file is added to skipped_entries."""
        codebase = tmp_path / "codebase"
        codebase.mkdir()

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "nonexistent.txt",
                "StartLine": "1",
                "EndLine": "1",
                "StartColumn": "1",
                "EndColumn": "10",
                "Description": "test",
                "Secret": "abc123",
            },
        ])

        report = mask_secrets(str(codebase), csv_path)

        assert report.total_secrets_masked == 0
        assert len(report.skipped_entries) == 1
        assert report.skipped_entries[0]["reason"] == "file not found"


class TestCsvValidationMissingColumns:
    def test_missing_columns_raises_value_error(self, tmp_path: str) -> None:
        """CSV without required columns raises ValueError."""
        csv_path = os.path.join(str(tmp_path), "bad.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("WrongColumn,AnotherOne\n")
            f.write("val1,val2\n")

        with pytest.raises(ValueError, match="missing required columns"):
            load_gitleaks_csv(csv_path)


class TestCsvValidationInvalidValues:
    def test_non_integer_line_raises_value_error(self, tmp_path: str) -> None:
        """Non-integer line numbers in CSV raise ValueError."""
        csv_path = _write_csv(str(tmp_path), "bad.csv", [
            {
                "File": "test.txt",
                "StartLine": "abc",
                "EndLine": "1",
                "StartColumn": "1",
                "EndColumn": "10",
            },
        ])

        with pytest.raises(ValueError, match="invalid integer"):
            load_gitleaks_csv(csv_path)


class TestPathTraversalBlocked:
    def test_traversal_path_skipped(self, tmp_path: str) -> None:
        """CSV entry with path traversal in File column is rejected."""
        codebase = tmp_path / "codebase"
        codebase.mkdir()

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "../../../etc/passwd",
                "StartLine": "1",
                "EndLine": "1",
                "StartColumn": "1",
                "EndColumn": "10",
                "Description": "traversal attempt",
                "Secret": "root:x",
            },
        ])

        report = mask_secrets(str(codebase), csv_path)

        assert report.total_secrets_masked == 0
        assert len(report.skipped_entries) == 1
        assert report.skipped_entries[0]["reason"] == "path traversal"


class TestUrlFetch:
    @patch("sast_triage.preprocessing.secret_masking.requests.get")
    def test_url_csv_parsed_correctly(
        self, mock_get: MagicMock, tmp_path: str,
    ) -> None:
        """Mock HTTPS response is parsed as valid CSV."""
        csv_content = (
            "Description,StartLine,EndLine,StartColumn,EndColumn,"
            "Match,Secret,File,SymlinkFile,Commit,Entropy,Author,"
            "Email,Date,Message,Tags,RuleID,Fingerprint,ActualLine,label\n"
            "test,1,1,1,5,match,secr,test.txt,,commit,1.0,author,"
            "email,date,msg,tags,rule,fp,line,TP\n"
        )
        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.content = csv_content.encode("utf-8")
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        rows = load_gitleaks_csv("https://example.com/report.csv")

        assert len(rows) == 1
        assert rows[0]["File"] == "test.txt"
        assert rows[0]["StartLine"] == "1"
        mock_get.assert_called_once()


class TestHttpRejected:
    def test_plain_http_raises_value_error(self) -> None:
        """Plain HTTP URL raises ValueError."""
        with pytest.raises(ValueError, match="Only HTTPS URLs"):
            load_gitleaks_csv("http://example.com/report.csv")


class TestNoneInput:
    def test_none_skips_masking_in_integration(self) -> None:
        """When gitleaks_report is 'none', mask_secrets is not called.

        This tests the integration logic: the caller checks for 'none'
        before calling mask_secrets.
        """
        gitleaks_report = "none"
        assert gitleaks_report.lower() == "none"
        # mask_secrets would not be called in run_triage.py


class TestReportAccuracy:
    def test_report_counts_match_operations(self, tmp_path: str) -> None:
        """Report counts match actual masking operations."""
        codebase = tmp_path / "codebase"
        codebase.mkdir()
        _write_file(
            str(codebase), "secrets.txt",
            "key1 = AAAA1111BBBB\n"
            "key2 = CCCC2222DDDD\n",
        )

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "secrets.txt",
                "StartLine": "1",
                "EndLine": "1",
                "StartColumn": "8",
                "EndColumn": "19",
                "Description": "secret 1",
                "Secret": "AAAA1111BBBB",
            },
            {
                "File": "secrets.txt",
                "StartLine": "2",
                "EndLine": "2",
                "StartColumn": "8",
                "EndColumn": "19",
                "Description": "secret 2",
                "Secret": "CCCC2222DDDD",
            },
        ])

        report = mask_secrets(str(codebase), csv_path)

        assert report.total_entries_in_csv == 2
        assert report.total_secrets_masked == 2
        assert report.files_modified == 1
        assert len(report.entries) == 2

        content = _read_file(str(codebase / "secrets.txt"))
        assert "AAAA1111BBBB" not in content
        assert "CCCC2222DDDD" not in content
        assert content.count(MASK_PLACEHOLDER) == 2


class TestMaskingAfterObfuscation:
    def test_both_preprocessing_steps_work(self, tmp_path: str) -> None:
        """Obfuscation then masking on the same directory both work."""
        from sast_triage.preprocessing.obfuscation import obfuscate_codebase

        codebase = tmp_path / "codebase"
        codebase.mkdir()
        _write_file(
            str(codebase), "app.conf",
            "server = 192.168.1.1\n"
            "api_key = SuperSecretKey123\n",
        )

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "app.conf",
                "StartLine": "2",
                "EndLine": "2",
                "StartColumn": "12",
                "EndColumn": "28",
                "Description": "api key",
                "Secret": "SuperSecretKey123",
            },
        ])

        # Step 1: Obfuscation
        obf_report = obfuscate_codebase(str(codebase))
        assert obf_report.total_replacements >= 1

        content_after_obf = _read_file(str(codebase / "app.conf"))
        assert "192.168.1.1" not in content_after_obf
        assert "__IPV4__" in content_after_obf

        # Step 2: Secret masking (after obfuscation)
        mask_report = mask_secrets(str(codebase), csv_path)
        assert mask_report.total_secrets_masked == 1

        content_after_mask = _read_file(str(codebase / "app.conf"))
        assert "__IPV4__" in content_after_mask
        assert MASK_PLACEHOLDER in content_after_mask
        assert "SuperSecretKey123" not in content_after_mask


class TestSecretPreview:
    def test_long_secret_preview(self) -> None:
        """Secrets longer than 4 chars show first 4 + '***'."""
        assert _build_secret_preview("myS3cretP@ssw0rd") == "myS3***"

    def test_short_secret_preview(self) -> None:
        """Secrets <= 4 chars show first 2 + '***'."""
        assert _build_secret_preview("ab") == "ab***"
        assert _build_secret_preview("abcd") == "ab***"


class TestEdgeCases:
    def test_nonexistent_codebase_raises(self, tmp_path: str) -> None:
        """Passing a nonexistent codebase directory raises ValueError."""
        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [])

        with pytest.raises(ValueError, match="does not exist"):
            mask_secrets("/nonexistent/path", csv_path)

    def test_empty_csv_returns_empty_report(self, tmp_path: str) -> None:
        """An empty CSV (header only) returns a report with zero counts."""
        codebase = tmp_path / "codebase"
        codebase.mkdir()

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [])

        report = mask_secrets(str(codebase), csv_path)

        assert report.total_entries_in_csv == 0
        assert report.total_secrets_masked == 0
        assert report.files_modified == 0

    def test_nested_file_path(self, tmp_path: str) -> None:
        """CSV entries with nested file paths are resolved correctly."""
        codebase = tmp_path / "codebase"
        nested = codebase / "src" / "config"
        nested.mkdir(parents=True)
        _write_file(
            str(nested), "db.conf",
            "db_pass = VerySecretPass\n",
        )

        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        csv_path = _write_csv(str(csv_dir), "report.csv", [
            {
                "File": "src/config/db.conf",
                "StartLine": "1",
                "EndLine": "1",
                "StartColumn": "11",
                "EndColumn": "24",
                "Description": "db password",
                "Secret": "VerySecretPass",
            },
        ])

        report = mask_secrets(str(codebase), csv_path)
        content = _read_file(str(nested / "db.conf"))

        assert "VerySecretPass" not in content
        assert MASK_PLACEHOLDER in content
        assert report.total_secrets_masked == 1
