"""Tests for the benchmark runner's output layout."""

from unittest.mock import patch

from click.testing import CliRunner

from run_benchmark import run_benchmark


class TestBenchmarkRunSubdir:
    """The benchmark owns a single timestamped run folder; every project's
    results and the cross-dataset summary live under it."""

    def test_outputs_nested_under_run_timestamped_subdir(self) -> None:
        runner = CliRunner()
        with patch(
            "run_benchmark.resolve_vertex_config", return_value=("proj", "loc")
        ), patch("run_benchmark.os.listdir", return_value=[]), patch(
            "run_benchmark.DirectoryHelpers.timestamped_subdir",
            return_value="out/20260608_143000",
        ) as mock_ts, patch(
            "run_benchmark.BenchmarkHelpers.generate_summary_kpis"
        ) as mock_summary:
            result = runner.invoke(run_benchmark, ["--output", "out"])

        assert result.exit_code == 0, result.output
        mock_ts.assert_called_once_with("out")
        assert mock_summary.call_args.kwargs["output_dir"] == "out/20260608_143000"
