"""Tests for CLI sub-commands, parameter parsing, and state filtering."""

import pytest
from click.testing import CliRunner

from run_triage import cli, filter_findings_by_hashes, filter_findings_by_state


@pytest.fixture
def runner():
    """Provide a Click CLI test runner."""
    return CliRunner()


class TestRunSubcommand:
    def test_run_requires_project_name(self, runner: CliRunner) -> None:
        """run without project name shows an error."""
        result = runner.invoke(cli, ["run", "--gitleaks-report", "none"])
        assert result.exit_code != 0
        assert "Missing argument" in result.output

    def test_run_requires_gitleaks_report(self, runner: CliRunner) -> None:
        """run without --gitleaks-report shows an error."""
        result = runner.invoke(cli, ["run", "my-project"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_run_help_shows_states_option(self, runner: CliRunner) -> None:
        """run --help lists the --states option."""
        result = runner.invoke(cli, ["run", "--help"])
        assert result.exit_code == 0
        assert "--states" in result.output

    def test_run_help_shows_findings_option(self, runner: CliRunner) -> None:
        """run --help lists the --findings option."""
        result = runner.invoke(cli, ["run", "--help"])
        assert result.exit_code == 0
        assert "--findings" in result.output


class TestInteractiveSubcommand:
    def test_interactive_subcommand_exists(self, runner: CliRunner) -> None:
        """interactive sub-command is registered in the CLI group."""
        result = runner.invoke(cli, ["interactive", "--help"])
        assert result.exit_code == 0
        assert "interactive" in result.output.lower()

    def test_interactive_help_shows_verbose(self, runner: CliRunner) -> None:
        """interactive --help lists the -v/--verbose option."""
        result = runner.invoke(cli, ["interactive", "--help"])
        assert result.exit_code == 0
        assert "--verbose" in result.output


class TestCliGroup:
    def test_group_help_shows_both_commands(self, runner: CliRunner) -> None:
        """Top-level --help lists both run and interactive commands."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "run" in result.output
        assert "interactive" in result.output

    def test_unknown_subcommand_fails(self, runner: CliRunner) -> None:
        """An unknown sub-command produces an error."""
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0


class TestStateFilterLogic:
    def test_filter_by_single_state(self) -> None:
        """Filtering by a single state returns only matching findings."""
        findings = [
            {"resultHash": "a", "state": "TO_VERIFY"},
            {"resultHash": "b", "state": "CONFIRMED"},
            {"resultHash": "c", "state": "NOT_EXPLOITABLE"},
        ]
        result = filter_findings_by_state(findings, ["TO_VERIFY"])
        assert len(result) == 1
        assert result[0]["resultHash"] == "a"

    def test_filter_by_multiple_states(self) -> None:
        """Filtering by multiple states returns all matching findings."""
        findings = [
            {"resultHash": "a", "state": "TO_VERIFY"},
            {"resultHash": "b", "state": "CONFIRMED"},
            {"resultHash": "c", "state": "NOT_EXPLOITABLE"},
        ]
        result = filter_findings_by_state(findings, ["TO_VERIFY", "CONFIRMED"])
        assert len(result) == 2
        hashes = {f["resultHash"] for f in result}
        assert hashes == {"a", "b"}

    def test_filter_case_insensitive(self) -> None:
        """State filtering is case-insensitive."""
        findings = [
            {"resultHash": "a", "state": "to_verify"},
            {"resultHash": "b", "state": "CONFIRMED"},
        ]
        result = filter_findings_by_state(findings, ["TO_VERIFY"])
        assert len(result) == 1
        assert result[0]["resultHash"] == "a"

    def test_empty_state_list_returns_all(self) -> None:
        """An empty state list returns all findings (no filtering)."""
        findings = [
            {"resultHash": "a", "state": "TO_VERIFY"},
            {"resultHash": "b", "state": "CONFIRMED"},
        ]
        result = filter_findings_by_state(findings, [])
        assert len(result) == 2

    def test_filter_missing_state_field(self) -> None:
        """Findings without a state field are excluded when filtering."""
        findings = [
            {"resultHash": "a", "state": "TO_VERIFY"},
            {"resultHash": "b"},
        ]
        result = filter_findings_by_state(findings, ["TO_VERIFY"])
        assert len(result) == 1
        assert result[0]["resultHash"] == "a"

    def test_no_matches_returns_empty(self) -> None:
        """Filtering with no matching states returns empty list."""
        findings = [
            {"resultHash": "a", "state": "CONFIRMED"},
        ]
        result = filter_findings_by_state(findings, ["TO_VERIFY"])
        assert len(result) == 0


class TestHashFilterLogic:
    def test_keeps_only_requested_hashes(self) -> None:
        """Only findings whose resultHash is in the requested set are kept."""
        findings = [
            {"resultHash": "a"},
            {"resultHash": "b"},
            {"resultHash": "c"},
        ]
        result = filter_findings_by_hashes(findings, ["a", "c"])
        assert {f["resultHash"] for f in result} == {"a", "c"}

    def test_reads_top_level_result_hash(self) -> None:
        """Regression: must read resultHash from the top level, not data.resultHash.

        /api/sast-results returns the hash at the top level. A previous version
        looked under finding["data"]["resultHash"] (the /api/results shape) and
        silently matched nothing.
        """
        findings = [
            {"resultHash": "a", "data": {"resultHash": "wrong"}},
        ]
        assert filter_findings_by_hashes(findings, ["a"]) == findings
        assert filter_findings_by_hashes(findings, ["wrong"]) == []


class TestGitleaksValidation:
    def test_nonexistent_file_rejected(self, runner: CliRunner) -> None:
        """A non-existent gitleaks report path is rejected early."""
        result = runner.invoke(
            cli,
            ["run", "my-project", "--gitleaks-report", "/no/such/file.csv"],
        )
        assert result.exit_code != 0
        assert "File not found" in result.output

    def test_none_is_accepted(self, runner: CliRunner) -> None:
        """'none' is accepted as a valid gitleaks report value."""
        # This will fail later (missing env vars), but should pass validation
        result = runner.invoke(
            cli,
            ["run", "my-project", "--gitleaks-report", "none"],
        )
        # Should not fail with "File not found"
        assert "File not found" not in result.output

    def test_existing_file_accepted(self, runner: CliRunner, tmp_path) -> None:
        """An existing file path passes validation."""
        csv_file = tmp_path / "report.csv"
        csv_file.write_text("File,StartLine,EndLine,StartColumn,EndColumn\n")
        result = runner.invoke(
            cli,
            ["run", "my-project", "--gitleaks-report", str(csv_file)],
        )
        assert "File not found" not in result.output


class TestDefaultValues:
    def test_state_default_is_to_verify(self, runner: CliRunner) -> None:
        """Default --states value is TO_VERIFY."""
        result = runner.invoke(cli, ["run", "--help"])
        assert "TO_VERIFY" in result.output

    def test_severities_default(self, runner: CliRunner) -> None:
        """Default --severities value includes HIGH,MEDIUM."""
        result = runner.invoke(cli, ["run", "--help"])
        assert "HIGH,MEDIUM" in result.output
