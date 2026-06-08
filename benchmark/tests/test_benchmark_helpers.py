"""Tests for benchmark.benchmark_helpers path handling.

The harness reads the agent's assessment file and writes its own result and
KPI files. On Windows those paths can exceed the 260-char MAX_PATH limit (the
assessment filename repeats the long project name), so every file access must
route through ``io_safe``. io_safe is a no-op on POSIX, so these run unchanged
on Linux and macOS.
"""

from unittest.mock import mock_open, patch

from benchmark.benchmark_helpers import BenchmarkHelpers


class TestLongPathSafety:
    def test_enrich_globs_assessment_file_through_io_safe(self):
        with patch(
            "benchmark.benchmark_helpers.io_safe", side_effect=lambda p: p
        ) as mock_io_safe, patch(
            "benchmark.benchmark_helpers.glob_module.glob", return_value=[]
        ) as mock_glob, patch(
            "benchmark.benchmark_helpers.json.load",
            return_value={"findings": []},
        ), patch("builtins.open", mock_open()):
            BenchmarkHelpers.enrich_dataset_with_triage_result(
                cxone_project_name="proj",
                dataset_filepath="datasets/proj_benchmark.json",
                output_dir="out/proj",
            )

        # The glob base (the output dir holding the assessment file) is
        # io_safe'd, so a >260 assessment path is matched and opened through
        # the long-path prefix.
        mock_io_safe.assert_any_call("out/proj")
        pattern = mock_glob.call_args.args[0]
        assert "out/proj" in pattern

    def test_summary_kpis_write_routes_through_io_safe(self):
        opener = mock_open()
        with patch(
            "benchmark.benchmark_helpers.io_safe",
            side_effect=lambda p: f"<safe>{p}",
        ), patch(
            "benchmark.benchmark_helpers.build_full_kpi_output", return_value={}
        ), patch("benchmark.benchmark_helpers.json.dump"), patch(
            "builtins.open", opener
        ):
            BenchmarkHelpers.generate_summary_kpis(
                model_name="model",
                all_datasets_data=[{"x": 1}],
                output_dir="outroot",
            )

        path_arg = opener.call_args.args[0]
        assert path_arg.startswith("<safe>")


class TestDatasetPathFromCaller:
    def test_enrich_reads_dataset_from_provided_path(self):
        # The dataset filename need not equal the project name (the on-disk
        # file may carry a `_benchmark` suffix). enrich must read the exact
        # path the runner already holds, not reconstruct `{project}.json`.
        opener = mock_open()
        with patch(
            "benchmark.benchmark_helpers.io_safe", side_effect=lambda p: p
        ), patch(
            "benchmark.benchmark_helpers.glob_module.glob", return_value=[]
        ), patch(
            "benchmark.benchmark_helpers.json.load",
            return_value={"findings": []},
        ), patch("builtins.open", opener):
            BenchmarkHelpers.enrich_dataset_with_triage_result(
                cxone_project_name="proj",
                dataset_filepath="datasets/proj_benchmark.json",
                output_dir="out/proj",
            )

        assert opener.call_args_list[0].args[0] == "datasets/proj_benchmark.json"
