"""Report generation utilities for SPECTR scanner"""

import json
import os
from datetime import datetime
from utils.colors import Colors

class ReportGenerator:
    """Generates various types of reports"""

    def __init__(self):
        self.reports_dir = "spectr_reports"
        self._ensure_reports_dir()

    def _ensure_reports_dir(self):
        """Ensure reports directory exists"""
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def generate_json_report(self, report_data):
        """Generate JSON format report"""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{self.reports_dir}/spectr_scan_{timestamp}.json"

        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            return filename
        except Exception as e:
            print(f"{Colors.RED}❌ Error saving report: {str(e)}{Colors.RESET}")
            return None
