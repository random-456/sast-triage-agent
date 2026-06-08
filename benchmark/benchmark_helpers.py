from pydantic import ValidationError
from typing import Dict, List
from datetime import datetime
import logging
import json
import statistics
import traceback
import os
import glob as glob_module

from benchmark.benchmark_models import DatasetProject, JustificationComparisonResult
from benchmark.benchmark_metrics import build_full_kpi_output
from benchmark.justification_check import JustificationAICheck

from config import BENCHMARK_DATASETS_DIR
from utils.path_helpers import io_safe

class BenchmarkHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def load_and_validate_dataset(self, filepath: str) -> Dict | None:
        """
        Method to load JSON datasets from benchmark/datasets

        Input:
        - Path to the dataset JSON file : string

        Output:
        - JSON dataset data : dict
        """

        self.logger.info(f"Loading {filepath}...")
        try:
            with open(io_safe(filepath), "r") as f:
                json_data = DatasetProject.model_validate_json(f.read())
                return json_data

        except FileNotFoundError:
            self.logger.error(f"The file '{filepath}' was not found.")
        except json.JSONDecodeError:
            self.logger.error(f"The file '{filepath}' is not valid JSON.")
        except ValidationError as e:
            self.logger.error(f"Validation failed! Found {e.error_count()} error(s):")
            self.logger.error(e)

        return None

    @staticmethod
    def _classification_to_result(is_vulnerable: bool | None) -> str:
        """Map an `is_vulnerable` classification to the analyst vocabulary."""
        if is_vulnerable is None:
            return "REFUSED"
        return "CONFIRMED" if is_vulnerable else "NOT_EXPLOITABLE"

    @classmethod
    def enrich_dataset_with_triage_result(self, cxone_project_name: str, output_dir: str) -> Dict | None:
        """
        Method to enrich the JSON data in the dataset with the agent triage results

        Input:
        - CxOne Project Name: str
        - Output Directory: str

        Output:
        - Enriched Daset Data: dict
        """
        self.logger.info(f"Enriching dataset data with results from triage ran on {cxone_project_name}...")

        try:
            # First we get the data from the dataset
            dataset_filepath = os.path.join(BENCHMARK_DATASETS_DIR, f"{cxone_project_name}.json")
            dataset_data = json.load(open(io_safe(dataset_filepath)))

            # Then we get the data from the assessment performed by the agent.
            # io_safe the glob base so a >260 assessment path is matched and the
            # returned path carries the long-path prefix for the open below.
            pattern = os.path.join(
                io_safe(output_dir),
                f"findings_assessment_{cxone_project_name}_*.json",
            )
            matches = sorted(glob_module.glob(pattern), key=os.path.getmtime, reverse=True)
            if not matches:
                self.logger.error(f"No assessment file found matching {pattern}")
                return None
            agent_assessment_filepath = matches[0]
            agent_assessment_data = json.load(open(agent_assessment_filepath))

            # Unwrap metadata envelope if present
            if isinstance(agent_assessment_data, dict) and "results" in agent_assessment_data:
                agent_assessment_data = agent_assessment_data["results"]

            # Then we get data for each finding and use it to enrich the dataset data
            enriched_dataset_data = dataset_data
            for finding in agent_assessment_data:
                finding_id = finding["resultHash"]
                # Compare on the classification, mapped to the analyst's
                # vocabulary. The disposition (suggested_state) may be
                # PROPOSED_NOT_EXPLOITABLE, which the analyst ground truth
                # never uses, so it is kept separate for operational metrics.
                agent_assessment_result = self._classification_to_result(
                    finding["is_vulnerable"]
                )
                agent_assessment_justification = finding["justification"]
                agent_assessment_confidence = finding["confidence"]

                dataset_assessment_finding = next(
                    (finding for finding in enriched_dataset_data['findings'] if finding['id'] == finding_id),
                    None  # Default value to return if no match is found
                )
                dataset_assessment_finding["agent_triage"] = {
                    "result": agent_assessment_result,
                    "justification": agent_assessment_justification,
                    "confidence": agent_assessment_confidence,
                    "is_vulnerable": finding["is_vulnerable"],
                    "suggested_state": finding["suggested_state"],
                }

            return enriched_dataset_data

        except Exception:
            self.logger.error(f"Unexpected error when enriching dataset data : {traceback.format_exc()}")

        return None

    @classmethod
    def compute_assessment_scores(self, project: str, location: str, dataset_data: Dict) -> Dict | None:
        """
        Method to compare the assessment made by the agent with the original assessment made in the dataset and provide a score for each finding

        Input:
        - Vertex Project Name : str
        - Vertex Location : str
        - Dataset Data (enriched with triage results) : dict

        Output:
        - Dataset Data (enriched with scores) : dict
        """
        self.logger.info(f"Computing scores for the provided dataset data...")

        if not dataset_data:
            self.logger.warning("Empty dataset data. Skipping scores computation...")
            return None

        try:
            enriched_dataset_data = dataset_data
            scores = []

            findings = enriched_dataset_data["findings"]
            for finding in findings:
                # First we retrieve result and justification for both the analyst and the agent triages
                analyst_assessment_result = finding["analyst_triage"]["result"]
                analyst_assessment_justification = finding["analyst_triage"]["justification"]

                agent_assessment_result = finding["agent_triage"]["result"]
                agent_assessment_justification = finding["agent_triage"]["justification"]
                agent_assessment_confidence = finding["agent_triage"]["confidence"]

                finding["confidence"] = agent_assessment_confidence

                # Now we compute the score
                # If the agent and the analyst don't come to the same conclusion => 0
                if agent_assessment_result != analyst_assessment_result:
                    self.logger.debug(f"Different result for finding {finding['id']} => 0")
                    scores.append(0)
                    finding["score"] = 0

                # Else we call a LLM to compare the justifications
                else:
                    justification_checker = JustificationAICheck(project, location)
                    result = justification_checker.compare_justifications(analyst_assessment_justification, agent_assessment_justification)

                    if result in JustificationComparisonResult.__members__:
                        score = JustificationComparisonResult[result].value

                        self.logger.debug(f"Justifications for {finding['id']} assessed as {result} => {score}")
                        scores.append(score)
                        finding["score"] = score
                    else:
                        self.logger.error(f"LLM failed to give a valid comparison result : {result}")
                        self.logger.error("No score computed for this finding...")

            # Finally we compute the median score and add it in the dataset JSON data
            average_score = statistics.mean(scores)
            enriched_dataset_data["average_score"] = average_score

            return enriched_dataset_data

        except Exception:
            self.logger.error(f"Unexpected error when computing score : {traceback.format_exc()}")

        return None

    @classmethod
    def save_enriched_datasets_data(self, model_name: str, enriched_datasets_data: Dict, output_dir: str) -> None:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        raw_results_filepath = os.path.join(output_dir, f"{timestamp}_{model_name.replace(' ', '-')}_benchmark_raw_results.json")

        try:
            json.dump(enriched_datasets_data, open(io_safe(raw_results_filepath), "w"), indent=4)
            self.logger.info(f"Saved enriched datasets data to {raw_results_filepath}")
        except:
            self.logger.error("Failed to save enriched datasets data")
            self.logger.error(traceback.format_exc())

    @classmethod
    def generate_kpis(
        self, model_name: str, raw_dataset_data: List, output_dir: str,
    ) -> None:
        """Generate KPI file for a single dataset."""
        try:
            if not raw_dataset_data:
                self.logger.warning("Empty dataset data. Skipping KPI generation...")
                return

            output = build_full_kpi_output(raw_dataset_data)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{timestamp}_{model_name.replace(' ', '-')}_benchmark_kpis.json"
            kpis_filepath = os.path.join(output_dir, filename)

            with open(io_safe(kpis_filepath), "w") as f:
                json.dump(output, f, indent=4)
            self.logger.info(f"Saved KPIs data to {kpis_filepath}")
        except Exception:
            self.logger.error("Failed to generate KPIs from enriched datasets data")
            self.logger.error(traceback.format_exc())

    @classmethod
    def generate_summary_kpis(
        self,
        model_name: str,
        all_datasets_data: List,
        output_dir: str,
    ) -> None:
        """Generate a cross-dataset summary KPI file at the output root."""
        try:
            if not all_datasets_data:
                self.logger.warning(
                    "No datasets data for summary. Skipping..."
                )
                return

            output = build_full_kpi_output(all_datasets_data)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = (
                f"{timestamp}_{model_name.replace(' ', '-')}"
                "_benchmark_summary.json"
            )
            summary_filepath = os.path.join(output_dir, filename)

            with open(io_safe(summary_filepath), "w") as f:
                json.dump(output, f, indent=4)
            self.logger.info(f"Saved summary KPIs to {summary_filepath}")
        except Exception:
            self.logger.error("Failed to generate summary KPIs")
            self.logger.error(traceback.format_exc())