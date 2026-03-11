import os
import csv
import json
import logging
from typing import List

from config import FINDINGS_CSV_FILE, FINDINGS_DIR, FINDINGS_JSON_FILE

class FindingsHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def save_findings_data(self, triage_records: List[dict], detailed_records: List[dict]) -> None:
        """Save findings data to CSV and JSON files."""

        os.makedirs(FINDINGS_DIR, exist_ok=True)

        # Write CSV file
        self.logger.info(f"Saving {len(triage_records)} records to {FINDINGS_CSV_FILE}...")

        with open(FINDINGS_CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["resultHash", "severity", "state", "triaged"])
            writer.writeheader()
            writer.writerows(triage_records)

        # Write JSON file
        self.logger.info(f"Saving detailed records to {FINDINGS_JSON_FILE}...")

        with open(FINDINGS_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(detailed_records, f, indent=4)

        self.logger.info("Findings data saved successfully")