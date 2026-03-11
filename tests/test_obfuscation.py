"""Tests for the obfuscation preprocessing module."""

import os

import pytest

from sast_triage.preprocessing.obfuscation import (
    ObfuscationReport,
    _is_binary_file,
    obfuscate_codebase,
)


def _write_file(directory: str, name: str, content: str) -> str:
    """Helper to create a text file and return its path."""
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _read_file(path: str) -> str:
    """Helper to read a file's content."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestIpv4Obfuscation:
    def test_ipv4_replaced(self, tmp_path: str) -> None:
        """IPv4 addresses are replaced with __IPV4__ placeholder."""
        _write_file(tmp_path, "config.txt", "server = 192.168.1.1\n")
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(tmp_path, "config.txt"))
        assert "192.168.1.1" not in content
        assert "__IPV4__" in content
        assert report.total_replacements >= 1
        assert report.replacements_by_type.get("IPV4", 0) >= 1


class TestIpv6Obfuscation:
    def test_ipv6_replaced(self, tmp_path: str) -> None:
        """IPv6 addresses are replaced with __IPV6__ placeholder."""
        _write_file(
            tmp_path,
            "network.conf",
            "addr = 2001:0db8:85a3::8a2e:0370:7334\n",
        )
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(tmp_path, "network.conf"))
        assert "2001:0db8:85a3" not in content
        assert "__IPV6__" in content
        assert report.replacements_by_type.get("IPV6", 0) >= 1


class TestMacObfuscation:
    def test_mac_replaced(self, tmp_path: str) -> None:
        """MAC addresses are replaced with __MAC__ placeholder."""
        _write_file(
            tmp_path, "devices.txt", "mac = 00:1A:2B:3C:4D:5E\n"
        )
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(tmp_path, "devices.txt"))
        assert "00:1A:2B:3C:4D:5E" not in content
        assert "__MAC__" in content
        assert report.replacements_by_type.get("MAC", 0) >= 1


class TestFqdnObfuscation:
    def test_fqdn_abcorg_replaced(self, tmp_path: str) -> None:
        """FQDNs ending in abcorg.com are replaced with __FQDN__ placeholder."""
        _write_file(
            tmp_path,
            "hosts.txt",
            "host = server.internal.abcorg.com\n",
        )
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(tmp_path, "hosts.txt"))
        assert "server.internal.abcorg.com" not in content
        assert "__FQDN__" in content
        assert report.replacements_by_type.get("FQDN", 0) >= 1

    def test_fqdn_corp_replaced(self, tmp_path: str) -> None:
        """FQDNs ending in .corp are replaced with __FQDN__ placeholder."""
        _write_file(
            tmp_path, "hosts.txt", "host = host.division.corp\n"
        )
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(tmp_path, "hosts.txt"))
        assert "host.division.corp" not in content
        assert "__FQDN__" in content
        assert report.replacements_by_type.get("FQDN", 0) >= 1


class TestBinaryFileSkipped:
    def test_binary_by_extension(self, tmp_path: str) -> None:
        """Binary files detected by extension are not modified."""
        bin_path = os.path.join(tmp_path, "image.png")
        original = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        with open(bin_path, "wb") as f:
            f.write(original)

        obfuscate_codebase(str(tmp_path))

        with open(bin_path, "rb") as f:
            assert f.read() == original

    def test_binary_by_content(self, tmp_path: str) -> None:
        """Files with non-UTF-8 content are skipped."""
        bin_path = os.path.join(tmp_path, "data.custom")
        original = bytes(range(256))
        with open(bin_path, "wb") as f:
            f.write(original)

        obfuscate_codebase(str(tmp_path))

        with open(bin_path, "rb") as f:
            assert f.read() == original


class TestMultiplePatternsInOneFile:
    def test_mixed_patterns_all_replaced(self, tmp_path: str) -> None:
        """A file with multiple pattern types has all of them replaced."""
        content = (
            "ip = 10.0.0.1\n"
            "mac = AA:BB:CC:DD:EE:FF\n"
            "host = app.prod.abcorg.com\n"
        )
        _write_file(tmp_path, "mixed.conf", content)
        report = obfuscate_codebase(str(tmp_path))

        result = _read_file(os.path.join(tmp_path, "mixed.conf"))
        assert "10.0.0.1" not in result
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert "app.prod.abcorg.com" not in result
        assert "__IPV4__" in result
        assert "__MAC__" in result
        assert "__FQDN__" in result
        assert report.total_replacements >= 3
        assert report.total_files_modified == 1


class TestNoMatches:
    def test_content_unchanged(self, tmp_path: str) -> None:
        """Files without sensitive patterns are left unchanged."""
        original = "just some normal text\nno patterns here\n"
        _write_file(tmp_path, "safe.txt", original)
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(tmp_path, "safe.txt"))
        assert content == original
        assert report.total_replacements == 0
        assert report.total_files_modified == 0
        assert report.total_files_processed == 1


class TestReportAccuracy:
    def test_counts_match_entries(self, tmp_path: str) -> None:
        """Report counts match the actual number of entries."""
        content = (
            "a = 192.168.1.1\n"
            "b = 10.0.0.1\n"
            "c = AA:BB:CC:DD:EE:FF\n"
        )
        _write_file(tmp_path, "multi.txt", content)
        report = obfuscate_codebase(str(tmp_path))

        assert report.total_replacements == len(report.entries)
        type_counts: dict[str, int] = {}
        for entry in report.entries:
            type_counts[entry.pattern_type] = (
                type_counts.get(entry.pattern_type, 0) + 1
            )
        assert type_counts == report.replacements_by_type

    def test_entry_details_correct(self, tmp_path: str) -> None:
        """Each ObfuscationEntry records the correct file, line, and original."""
        _write_file(
            tmp_path, "test.cfg", "line1\nip = 172.16.0.1\nline3\n"
        )
        report = obfuscate_codebase(str(tmp_path))

        ipv4_entries = [
            e for e in report.entries if e.pattern_type == "IPV4"
        ]
        assert len(ipv4_entries) >= 1
        entry = ipv4_entries[0]
        assert entry.file == "test.cfg"
        assert entry.line == 2
        assert entry.original == "172.16.0.1"


class TestEmptyDirectory:
    def test_empty_dir_returns_empty_report(self, tmp_path: str) -> None:
        """An empty codebase directory returns an empty report."""
        report = obfuscate_codebase(str(tmp_path))

        assert report.total_files_processed == 0
        assert report.total_files_modified == 0
        assert report.total_replacements == 0
        assert report.entries == []


class TestEdgeCases:
    def test_nonexistent_dir_raises(self) -> None:
        """Passing a nonexistent directory raises ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            obfuscate_codebase("/nonexistent/path/to/codebase")

    def test_nested_directories(self, tmp_path: str) -> None:
        """Files in nested subdirectories are processed."""
        nested = os.path.join(tmp_path, "src", "config")
        os.makedirs(nested)
        _write_file(nested, "db.conf", "host = 10.20.30.40\n")
        report = obfuscate_codebase(str(tmp_path))

        content = _read_file(os.path.join(nested, "db.conf"))
        assert "__IPV4__" in content
        assert report.total_files_modified == 1

    def test_is_binary_file_with_text(self, tmp_path: str) -> None:
        """Text files are correctly identified as non-binary."""
        path = _write_file(tmp_path, "readme.md", "Hello world\n")
        assert _is_binary_file(path) is False

    def test_is_binary_file_with_known_extension(
        self, tmp_path: str
    ) -> None:
        """Files with known binary extensions are detected."""
        path = os.path.join(tmp_path, "archive.jar")
        with open(path, "wb") as f:
            f.write(b"\x00" * 10)
        assert _is_binary_file(path) is True
