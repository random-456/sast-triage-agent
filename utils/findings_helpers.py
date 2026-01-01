import os
import json
import logging
from typing import List


class FindingsHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def save_findings_data(
        self,
        detailed_records: List[dict],
        findings_dir: str,
        findings_json_file: str
    ) -> None:
        """
        Save findings data to JSON file only.

        Args:
            detailed_records: List of detailed finding records with agent_analyzed field
            findings_dir: Directory to save findings (REQUIRED - use PathManager)
            findings_json_file: Path to JSON file (REQUIRED - use PathManager)
        """
        os.makedirs(findings_dir, exist_ok=True)

        # Write JSON file
        self.logger.info(f"Saving {len(detailed_records)} records to {findings_json_file}...")

        with open(findings_json_file, "w", encoding="utf-8") as f:
            json.dump(detailed_records, f, indent=4)

        self.logger.info("Findings data saved successfully")