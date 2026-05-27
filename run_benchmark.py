import click
from click.testing import CliRunner
import os
import logging

from utils.banner import display_banner
from utils.generic_logging import setup_logging
from benchmark.benchmark_helpers import BenchmarkHelpers
from run_triage import cli

from config import DEFAULT_OUTPUT_DIR, APP_NAME, BENCHMARK_DATASETS_DIR, BENCHMARK_SECRET_REPORTS_DIR, DEFAULT_TRIAGE_MODEL, resolve_vertex_config

@click.command()
@click.option("--model", "model_name", default=DEFAULT_TRIAGE_MODEL, help="AI Model used for analysis")
@click.option("--output", "output_dir", default=DEFAULT_OUTPUT_DIR, help="Output directory")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option(
    "--compact-logs",
    is_flag=True,
    help=(
        "Forward --compact-logs to each run_triage invocation. "
        "Reduced agent log; for development analysis only."
    ),
)
def run_benchmark(model_name: str, output_dir: str, verbose: bool, compact_logs: bool):
    """
    Run a benchmark based on a defined set of CheckmarxOne findings. Results are saved to the chosen output directory.
    """
    display_banner(f"{APP_NAME} - Benchmark")

    setup_logging(level=logging.DEBUG) if verbose else setup_logging(level=logging.INFO)
    logger = logging.getLogger("run_benchmark")

    runner = CliRunner()
    gcp_project, gcp_location = resolve_vertex_config()

    datasets = [os.path.join(BENCHMARK_DATASETS_DIR, f) for f in os.listdir(BENCHMARK_DATASETS_DIR) if f.endswith(".json")]
    logger.info(f"Found {len(datasets)} datasets to evaluate !")

    all_datasets_data = []

    for dataset in datasets:
        json_data = BenchmarkHelpers.load_and_validate_dataset(dataset)

        if json_data:
            project_name = json_data.project
            finding_ids = [finding.id for finding in json_data.findings]

            dataset_basename = os.path.splitext(os.path.basename(dataset))[0]
            gitleaks_report = os.path.join(BENCHMARK_SECRET_REPORTS_DIR, f"{dataset_basename}.csv")
            if not os.path.isfile(gitleaks_report):
                logger.error(
                    f"Missing secrets report for dataset '{dataset_basename}': "
                    f"expected {os.path.abspath(gitleaks_report)}. Skipping."
                )
                continue

            logger.info(f"Performing triage for {len(finding_ids)} findings...")

            project_output_dir = os.path.join(output_dir, project_name)
            os.makedirs(project_output_dir, exist_ok=True)

            parameters = [project_name, "--findings", ",".join(finding_ids), "--model", model_name, "--output", project_output_dir, "--gitleaks-report", gitleaks_report]
            if compact_logs:
                parameters.append("--compact-logs")

            logger.debug(f"Launching run_triage command with parameters : {' '.join(parameters)}")
            result = runner.invoke(cli, ["run"] + parameters)

            # Re-setting up logging as it will have been closed when finishin the run_triage
            setup_logging(level=logging.DEBUG) if verbose else setup_logging(level=logging.INFO)
            logger = logging.getLogger("run_benchmark")

            if result.exit_code == 0:
                logger.info("Command executed successfully!")

                dataset_data_with_triage_results = BenchmarkHelpers.enrich_dataset_with_triage_result(
                    cxone_project_name=project_name,
                    output_dir=project_output_dir
                )

                dataset_data_with_scores = BenchmarkHelpers.compute_assessment_scores(
                    project=gcp_project,
                    location=gcp_location,
                    dataset_data=dataset_data_with_triage_results
                )

                if dataset_data_with_scores:
                    # Then we save the benchmarking raw results to a JSON file
                    BenchmarkHelpers.save_enriched_datasets_data(
                        model_name=model_name,
                        enriched_datasets_data=[dataset_data_with_scores],
                        output_dir=project_output_dir
                    )

                    # Finally we compute KPIs from the benchmarking results and save them to a JSON file
                    BenchmarkHelpers.generate_kpis(
                        model_name=model_name,
                        raw_dataset_data=[dataset_data_with_scores],
                        output_dir=project_output_dir
                    )

                    all_datasets_data.append(dataset_data_with_scores)
            else:
                logger.error("Command failed!")
                logger.error(result.exception)

    # Generate cross-dataset summary KPIs
    BenchmarkHelpers.generate_summary_kpis(
        model_name=model_name,
        all_datasets_data=all_datasets_data,
        output_dir=output_dir,
    )

if __name__ == "__main__":
    run_benchmark()