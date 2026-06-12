"""Tests for CLI sub-commands, parameter parsing, and state filtering."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from run_triage import (
    cli,
    execute_triage,
    filter_findings_by_hashes,
    filter_findings_by_state,
)
from utils.llm_factory import ModelSelection


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


class TestModelFlags:
    """``run`` exposes a global ``--model`` plus per-node model and location
    flags, bundled into a ModelSelection passed to execute_triage."""

    def test_run_help_lists_per_node_model_and_location_flags(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(cli, ["run", "--help"])
        assert result.exit_code == 0
        for flag in (
            "--research-model",
            "--analyst-model",
            "--critic-model",
            "--research-location",
            "--analyst-location",
            "--critic-location",
        ):
            assert flag in result.output

    def test_flags_are_bundled_into_model_selection(self, runner: CliRunner) -> None:
        with patch("run_triage.execute_triage") as mock_exec:
            runner.invoke(
                cli,
                [
                    "run",
                    "proj",
                    "--gitleaks-report",
                    "none",
                    "--model",
                    "gemini-2.5-flash",
                    "--critic-model",
                    "claude-sonnet-4@20250514",
                    "--critic-location",
                    "us-east5",
                ],
            )
        selection = mock_exec.call_args.kwargs["model_selection"]
        assert selection.model == "gemini-2.5-flash"
        assert selection.critic_model == "claude-sonnet-4@20250514"
        assert selection.critic_location == "us-east5"
        assert selection.research_model is None


class TestRunSubdirFlag:
    """``run`` groups each invocation's output under a timestamped subfolder
    by default; ``--no-run-subdir`` writes straight into ``--output`` (used by
    the benchmark, which owns its own run folder)."""

    def test_run_creates_run_subdir_by_default(self, runner: CliRunner) -> None:
        with patch("run_triage.execute_triage") as mock_exec:
            runner.invoke(cli, ["run", "proj", "--gitleaks-report", "none"])
        assert mock_exec.call_args.kwargs["create_run_subdir"] is True

    def test_no_run_subdir_flag_disables_run_subdir(self, runner: CliRunner) -> None:
        with patch("run_triage.execute_triage") as mock_exec:
            runner.invoke(
                cli, ["run", "proj", "--gitleaks-report", "none", "--no-run-subdir"]
            )
        assert mock_exec.call_args.kwargs["create_run_subdir"] is False


class TestExecuteTriageRunSubdir:
    """``execute_triage`` resolves the run subfolder before setting up
    directories, so every downstream write lands inside it."""

    @staticmethod
    def _client_that_aborts() -> MagicMock:
        # No project match forces an early sys.exit(1), after directory setup.
        client = MagicMock()
        client.get_project_id_by_name.return_value = None
        return client

    def test_output_dir_nested_when_run_subdir_enabled(self, monkeypatch) -> None:
        monkeypatch.setenv("BASE_URL", "https://cx.example")
        monkeypatch.setenv("REFRESH_TOKEN", "tok")
        with patch(
            "run_triage.DirectoryHelpers.timestamped_subdir",
            return_value="out/20260608_143000",
        ) as mock_ts, patch(
            "run_triage.DirectoryHelpers.setup_directories"
        ) as mock_setup, patch(
            "run_triage.CheckmarxClient", return_value=self._client_that_aborts()
        ):
            with pytest.raises(SystemExit):
                execute_triage(
                    project_name="proj",
                    model_selection=ModelSelection(model="m"),
                    severity_list=["HIGH"],
                    state_list=["TO_VERIFY"],
                    branch="main",
                    output_dir="out",
                    gitleaks_report="none",
                    keep_temp=False,
                    finding_hashes=None,
                    create_run_subdir=True,
                )

        mock_ts.assert_called_once_with("out")
        assert mock_setup.call_args.args[0] == "out/20260608_143000"

    def test_output_dir_unchanged_when_run_subdir_disabled(self, monkeypatch) -> None:
        monkeypatch.setenv("BASE_URL", "https://cx.example")
        monkeypatch.setenv("REFRESH_TOKEN", "tok")
        with patch(
            "run_triage.DirectoryHelpers.timestamped_subdir"
        ) as mock_ts, patch(
            "run_triage.DirectoryHelpers.setup_directories"
        ) as mock_setup, patch(
            "run_triage.CheckmarxClient", return_value=self._client_that_aborts()
        ):
            with pytest.raises(SystemExit):
                execute_triage(
                    project_name="proj",
                    model_selection=ModelSelection(model="m"),
                    severity_list=["HIGH"],
                    state_list=["TO_VERIFY"],
                    branch="main",
                    output_dir="out",
                    gitleaks_report="none",
                    keep_temp=False,
                    finding_hashes=None,
                    create_run_subdir=False,
                )

        mock_ts.assert_not_called()
        assert mock_setup.call_args.args[0] == "out"


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
