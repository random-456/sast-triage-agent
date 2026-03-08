from pydantic import ValidationError
from typing import Dict, List
from collections import defaultdict
from datetime import datetime
import logging
import json
import statistics
import traceback
import os

from benchmark.benchmark_models import DatasetProject, JustificationComparisonResult
from benchmark.justification_check import JustificationAICheck

from config import BENCHMARK_DATASETS_DIR

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
            with open(filepath, "r") as f:
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
            dataset_data = json.load(open(dataset_filepath))

            # Then we get the data from the assessment performed by the agent
            agent_assessment_filepath = os.path.join(output_dir, f"findings_assessment_{cxone_project_name}.json")
            agent_assessment_data = json.load(open(agent_assessment_filepath))

            # Then we get data for each finding and use it to enrich the dataset data
            enriched_dataset_data = dataset_data
            for finding in agent_assessment_data:
                finding_id = finding["resultHash"]
                agent_assessment_result = finding["assessment_result"]
                agent_assessment_justification = finding["assessment_justification"]
                agent_assessment_confidence = finding["assessment_confidence"]

                dataset_assessment_finding = next(
                    (finding for finding in enriched_dataset_data['findings'] if finding['id'] == finding_id),
                    None  # Default value to return if no match is found
                )
                dataset_assessment_finding["agent_triage"] = {
                    "result": agent_assessment_result,
                    "justification": agent_assessment_justification,
                    "confidence": agent_assessment_confidence
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
            json.dump(enriched_datasets_data, open(raw_results_filepath, "w"), indent=4)
            self.logger.info(f"Saved enriched datasets data to {raw_results_filepath}")
        except:
            self.logger.error("Failed to save enriched datasets data")
            self.logger.error(traceback.format_exc())

    @classmethod
    def generate_kpis(self, model_name: str, raw_dataset_data: List, output_dir: str) -> None:
        try:
            if not raw_dataset_data:
                self.logger.warning("Empty dataset data. Skipping KPI generation...")
                return

            language_data, category_data, complexity_data, severity_data = (
                defaultdict(lambda: {
                    "total_count": 0,
                    "accurate_count": 0,
                    "cumulated_score": 0,
                    "cumulated_confidence": 0
                }) for _ in range(4)
            )
            cumulated_average_score = 0

            for project in raw_dataset_data:
                findings = project.get("findings", [])
                project_average_score = project.get("average_score", 0)
                cumulated_average_score += project_average_score

                for finding in findings:
                    language = finding.get("language")
                    category = finding.get("category")
                    complexity = finding.get("complexity")
                    severity = finding.get("severity")

                    analyst_triage_result = finding.get("analyst_triage", {}).get("result", 0)
                    agent_triage_result = finding.get("agent_triage", {}).get("result", 0)
                    is_accurate = 1 if analyst_triage_result == agent_triage_result else 0

                    score = finding.get("score", 0)
                    confidence = finding.get("confidence", 0)

                    language_stats = language_data[language]
                    category_stats = category_data[category]
                    complexity_stats = complexity_data[complexity]
                    severity_stats = severity_data[severity]

                    for stats in [language_stats, category_stats, complexity_stats, severity_stats]:
                        stats["total_count"] += 1
                        stats["accurate_count"] += is_accurate
                        stats["cumulated_score"] += score
                        stats["cumulated_confidence"] += confidence

            output = {
                "average_score": cumulated_average_score / len(raw_dataset_data)
            }

            aggregated_data = {
                "language": language_data,
                "category": category_data,
                "complexity": complexity_data,
                "severity": severity_data
            }

            for criteria in aggregated_data:
                criteria_kpi_data = []
                aggregated_criteria_data = aggregated_data.get(criteria)

                for criteria_entry in aggregated_criteria_data:
                    criteria_entry_value = aggregated_criteria_data.get(criteria_entry)
                    criteria_kpi_data.append({
                        criteria_entry: {
                            "average_accuracy": criteria_entry_value["accurate_count"] / criteria_entry_value["total_count"] * 100,
                            "average_score": criteria_entry_value["cumulated_score"] / criteria_entry_value["total_count"],
                            "average_confidence": criteria_entry_value["cumulated_confidence"] / criteria_entry_value["total_count"]
                        }
                    })

                output[f"{criteria}_kpi"] = criteria_kpi_data

            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            kpis_filepath = os.path.join(output_dir, f"{timestamp}_{model_name.replace(' ', '-')}_benchmark_kpis.json")

            json.dump(output, open(kpis_filepath, "w"), indent=4)
            self.logger.info(f"Saved KPIs data to {kpis_filepath}")
        except:
            self.logger.error("Failed to generate KPIs from enriched datasets data")
            self.logger.error(traceback.format_exc())