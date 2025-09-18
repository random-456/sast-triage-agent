"""HTML report generator for SAST triage results."""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List


class ReportGenerator:
    """Generate progressive HTML reports for SAST findings."""
    
    def __init__(self, output_dir: str = ".", project_name: Optional[str] = None,
                 project_id: Optional[str] = None, scan_id: Optional[str] = None, 
                 base_url: Optional[str] = None, branch: Optional[str] = None,
                 model_name: Optional[str] = None):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save the report
            project_name: Project name for the report
            project_id: Project identifier for the report
            scan_id: Scan identifier for the report
            base_url: Checkmarx base URL for generating links
            branch: Git branch being analyzed
            model_name: LLM model used for analysis
        """
        self.output_dir = Path(output_dir)
        self.project_name = project_name or "Unknown"
        self.project_id = project_id or "Unknown"
        self.scan_id = scan_id
        self.base_url = base_url
        self.branch = branch
        self.model_name = model_name or "Unknown"
        
        # Generate timestamp-based filename
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        # Sanitize project name for filename
        safe_project_name = "".join(c if c.isalnum() or c in '-_' else '_' for c in self.project_name)
        filename = f"{timestamp}_triage_report_{safe_project_name}.html"
        self.report_path = self.output_dir / filename
        self.findings_data = []
        self.stats = {
            "total": 0,
            "confirmed": 0,
            "not_exploitable": 0,
            "refused": 0
        }
    
    def initialize_report(self, total_findings: int) -> None:
        """
        Create initial HTML report with header and empty container.
        
        Args:
            total_findings: Total number of findings to analyze
        """
        self.stats["total"] = total_findings
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Triage Report - {self.project_name}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .not-exploitable {{
            filter: grayscale(60%);
            opacity: 0.85;
        }}
        .finding-card {{
            transition: all 0.3s ease;
        }}
        .finding-card:hover {{
            transform: translateY(-2px);
        }}
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-7xl">
        <!-- Header -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <div class="flex items-center gap-4 mb-4">
                <h1 class="text-3xl font-bold text-gray-800">SAST Triage Report</h1>
                <span class="text-2xl font-semibold text-blue-600">|</span>
                <h2 class="text-2xl font-semibold text-blue-600">{self.project_name}</h2>
            </div>
            <!-- Project/Scan Information Row -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-3">
                <div>
                    <span class="font-semibold">Project ID:</span> 
                    {f'<a href="{self.base_url}/projects/{self.project_id}" target="_blank" class="text-blue-600 hover:underline">{self.project_id}</a>' if self.base_url else self.project_id}
                </div>
                {f'''<div>
                    <span class="font-semibold">Scan ID:</span> 
                    <a href="{self.base_url}/sast-results/{self.project_id}/{self.scan_id}" target="_blank" class="text-blue-600 hover:underline">{self.scan_id}</a>
                </div>''' if self.scan_id and self.base_url else '<div></div>'}
                {f'''<div>
                    <span class="font-semibold">Branch:</span> 
                    <span class="text-gray-700">{self.branch}</span>
                </div>''' if self.branch else '<div></div>'}
            </div>
            
            <!-- Analysis Information Row -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                <div>
                    <span class="font-semibold">Analysis Date:</span> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div>
                    <span class="font-semibold">Analysis Model:</span> 
                    <span class="text-gray-700">{self.model_name}</span>
                </div>
                <div></div>
            </div>
            
            <!-- Statistics -->
            <div class="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4" id="stats">
                <div class="bg-gray-100 p-3 rounded">
                    <div class="text-2xl font-bold text-gray-700" id="stat-total">{total_findings}</div>
                    <div class="text-xs text-gray-600">Total Findings Analyzed</div>
                </div>
                <div class="bg-red-50 p-3 rounded">
                    <div class="text-2xl font-bold text-red-600" id="stat-confirmed">0</div>
                    <div class="text-xs text-gray-600">Confirmed</div>
                </div>
                <div class="bg-green-50 p-3 rounded">
                    <div class="text-2xl font-bold text-green-600" id="stat-not-exploitable">0</div>
                    <div class="text-xs text-gray-600">Not Exploitable</div>
                </div>
                <div class="bg-amber-50 p-3 rounded">
                    <div class="text-2xl font-bold text-amber-600" id="stat-refused">0</div>
                    <div class="text-xs text-gray-600">Refused</div>
                </div>
            </div>
        </div>
        
        <!-- Progress Bar -->
        <div id="progress-container" class="bg-white rounded-lg shadow-md p-4 mb-6">
            <div class="flex justify-between mb-2">
                <span class="text-sm font-semibold text-gray-700">Analysis Progress</span>
                <span class="text-sm text-gray-600" id="progress-text">Analyzing 0 of {total_findings} findings...</span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-3">
                <div id="progress-bar" class="bg-blue-600 h-3 rounded-full transition-all duration-300" style="width: 0%"></div>
            </div>
        </div>
        
        <!-- Sort/Filter Controls -->
        <div class="bg-white rounded-lg shadow-md p-4 mb-6">
            <div class="flex flex-wrap gap-4 items-center">
                <label class="text-sm font-semibold text-gray-700">Sort by:</label>
                <select id="sortBy" onchange="sortFindings()" class="px-3 py-1 border border-gray-300 rounded-md text-sm">
                    <option value="severity">Severity</option>
                    <option value="result">Assessment Result</option>
                    <option value="confidence">Confidence</option>
                    <option value="original">Original Order</option>
                </select>
                
                <label class="text-sm font-semibold text-gray-700 ml-4">Filter:</label>
                <select id="filterBy" onchange="filterFindings()" class="px-3 py-1 border border-gray-300 rounded-md text-sm">
                    <option value="all">All Findings</option>
                    <option value="confirmed">Confirmed Only</option>
                    <option value="not_exploitable">Not Exploitable Only</option>
                    <option value="refused">Refused Only</option>
                </select>
            </div>
        </div>
        
        <!-- Findings Container -->
        <div id="findings-container">
            <!-- Finding cards will be inserted here -->
        </div>
    </div>
    
    <script>
        let findingIndex = 0;
        
        function sortFindings() {{
            const container = document.getElementById('findings-container');
            const cards = Array.from(container.getElementsByClassName('finding-card'));
            const sortBy = document.getElementById('sortBy').value;
            
            cards.sort((a, b) => {{
                if (sortBy === 'severity') {{
                    const order = {{'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}};
                    return (order[b.dataset.severity] || 0) - (order[a.dataset.severity] || 0);
                }} else if (sortBy === 'result') {{
                    const order = {{'CONFIRMED': 3, 'REFUSED': 2, 'NOT_EXPLOITABLE': 1}};
                    return (order[b.dataset.result] || 0) - (order[a.dataset.result] || 0);
                }} else if (sortBy === 'confidence') {{
                    return parseFloat(b.dataset.confidence || 0) - parseFloat(a.dataset.confidence || 0);
                }} else if (sortBy === 'original') {{
                    return parseInt(a.dataset.index) - parseInt(b.dataset.index);
                }}
            }});
            
            cards.forEach(card => container.appendChild(card));
        }}
        
        function filterFindings() {{
            const filterBy = document.getElementById('filterBy').value;
            const cards = document.getElementsByClassName('finding-card');
            
            Array.from(cards).forEach(card => {{
                if (filterBy === 'all') {{
                    card.style.display = 'block';
                }} else {{
                    const result = card.dataset.result.toLowerCase().replace('_', '');
                    const filter = filterBy.replace('_', '');
                    card.style.display = result === filter ? 'block' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
        
        # Write initial report
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def add_finding(
        self, 
        finding_details: Dict, 
        assessment: Dict,
        current: int,
        total: int
    ) -> None:
        """
        Add a finding to the report and update progress.
        
        Args:
            finding_details: Finding details including dataflow
            assessment: Assessment result from triage
            current: Current finding number
            total: Total number of findings
        """
        # Update statistics
        result = assessment.get("assessment_result", "REFUSED").upper()
        if result == "CONFIRMED":
            self.stats["confirmed"] += 1
        elif result == "NOT_EXPLOITABLE":
            self.stats["not_exploitable"] += 1
        else:
            self.stats["refused"] += 1
        
        # Generate finding card HTML
        finding_html = self._generate_finding_card(
            finding_details, 
            assessment,
            current - 1  # Index for sorting
        )
        
        # Read current report
        with open(self.report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Insert finding card
        insertion_point = content.find('</div>\n    </div>\n    \n    <script>')
        if insertion_point == -1:
            insertion_point = content.find('<!-- Finding cards will be inserted here -->')
            if insertion_point != -1:
                insertion_point = content.find('\n', insertion_point)
        
        if insertion_point != -1:
            content = (
                content[:insertion_point] + 
                "\n" + finding_html + 
                content[insertion_point:]
            )
        
        # Update progress
        progress_percent = (current / total) * 100
        content = content.replace(
            f'id="progress-text">Analyzing {current-1} of {total}',
            f'id="progress-text">Analyzing {current} of {total}'
        )
        content = content.replace(
            f'style="width: {((current-1)/total)*100:.1f}%"',
            f'style="width: {progress_percent:.1f}%"'
        )
        
        # Update statistics
        content = content.replace(
            f'id="stat-confirmed">{self.stats["confirmed"]-1 if result == "CONFIRMED" else self.stats["confirmed"]}</div>',
            f'id="stat-confirmed">{self.stats["confirmed"]}</div>'
        )
        content = content.replace(
            f'id="stat-not-exploitable">{self.stats["not_exploitable"]-1 if result == "NOT_EXPLOITABLE" else self.stats["not_exploitable"]}</div>',
            f'id="stat-not-exploitable">{self.stats["not_exploitable"]}</div>'
        )
        content = content.replace(
            f'id="stat-refused">{self.stats["refused"]-1 if result == "REFUSED" else self.stats["refused"]}</div>',
            f'id="stat-refused">{self.stats["refused"]}</div>'
        )
        
        # Hide progress bar if complete
        if current == total:
            content = content.replace(
                '<div id="progress-container" class="bg-white rounded-lg shadow-md p-4 mb-6">',
                '<div id="progress-container" class="hidden">'
            )
        
        # Write updated report
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _generate_finding_card(
        self, 
        finding: Dict, 
        assessment: Dict,
        index: int
    ) -> str:
        """
        Generate HTML for a single finding card.
        
        Args:
            finding: Finding details
            assessment: Assessment result
            index: Finding index for sorting
            
        Returns:
            HTML string for the finding card
        """
        severity = finding.get("severity", "UNKNOWN")
        query_name = finding.get("queryName", "Unknown Query")
        category = finding.get("category", "")
        cwe_id = finding.get("cweID", "")
        finding_id = finding.get("findingId", "")
        
        result = assessment.get("assessment_result", "REFUSED")
        confidence = assessment.get("assessment_confidence", 0) * 100
        justification = assessment.get("assessment_justification", "No justification provided")
        
        # Get styling classes
        severity_classes = self._get_severity_classes(severity)
        result_classes = self._get_result_classes(result)
        card_classes = "not-exploitable" if result == "NOT_EXPLOITABLE" else ""
        
        # Format dataflow
        dataflow_html = self._format_dataflow(finding.get("dataflow", []))
        
        return f"""
        <div class="finding-card bg-white rounded-lg shadow-md mb-4 {card_classes}" 
             data-severity="{severity}" 
             data-result="{result}" 
             data-confidence="{confidence:.1f}"
             data-index="{index}">
            <!-- Header -->
            <div class="p-4 border-b border-gray-200 flex justify-between items-center">
                <div class="flex items-center gap-3">
                    <span class="{severity_classes}">{severity}</span>
                    {f'<span class="text-xs px-2 py-1 bg-gray-100 rounded">CWE-{cwe_id}</span>' if cwe_id else ''}
                </div>
                <div class="text-lg font-semibold text-gray-800">{query_name}</div>
            </div>
            
            <!-- Two-column layout -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
                <!-- Left: Dataflow -->
                <div class="md:border-r md:pr-4">
                    <h3 class="font-semibold text-gray-700 mb-3 flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"></path>
                        </svg>
                        Data Flow
                    </h3>
                    {dataflow_html}
                </div>
                
                <!-- Right: Assessment -->
                <div class="md:pl-4">
                    <h3 class="font-semibold text-gray-700 mb-3 flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        Assessment
                    </h3>
                    <div class="mb-3">
                        <span class="{result_classes}">{result.replace('_', ' ')}</span>
                        <span class="ml-2 text-sm text-gray-600">({confidence:.1f}% confidence)</span>
                    </div>
                    <div class="text-sm text-gray-700 leading-relaxed">
                        <p class="whitespace-pre-wrap">{justification}</p>
                    </div>
                </div>
            </div>
            
            <!-- Footer with finding ID -->
            <div class="px-4 py-2 bg-gray-50 border-t border-gray-200 rounded-b-lg">
                <span class="text-xs text-gray-500">Finding ID: {finding_id}</span>
            </div>
        </div>"""
    
    def _format_dataflow(self, dataflow: List[Dict]) -> str:
        """
        Format dataflow nodes as vertical HTML.
        
        Args:
            dataflow: List of dataflow nodes
            
        Returns:
            HTML string for dataflow visualization
        """
        if not dataflow:
            return '<div class="text-sm text-gray-500">No dataflow information available</div>'
        
        html_parts = ['<div class="space-y-2 text-xs">']
        
        for i, node in enumerate(dataflow):
            # Extract relevant fields (excluding the ones user doesn't want)
            file_path = node.get("fileName", "")
            if file_path.startswith("/"):
                file_path = file_path[1:]  # Remove leading slash for relative path
            
            line = node.get("line", "")
            method = node.get("method", "")
            name = node.get("name", "")
            
            # Determine node type
            is_source = i == 0
            is_sink = i == len(dataflow) - 1
            
            # Node styling
            if is_source:
                icon = "→"
                bg_class = "bg-blue-50 border-blue-200"
                label = "SOURCE"
                label_class = "text-blue-600"
            elif is_sink:
                icon = "⚠"
                bg_class = "bg-red-50 border-red-200"
                label = "SINK"
                label_class = "text-red-600"
            else:
                icon = "↓"
                bg_class = "bg-gray-50 border-gray-200"
                label = f"FLOW {i}"
                label_class = "text-gray-600"
            
            html_parts.append(f"""
                <div class="flex items-start {bg_class} border rounded p-2">
                    <span class="mr-2 text-lg">{icon}</span>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 mb-1">
                            <span class="font-semibold {label_class} text-xs">{label}</span>
                        </div>
                        <div class="font-mono text-gray-700 truncate" title="{file_path}:{line}">
                            {file_path}:<span class="font-bold">{line}</span>
                        </div>
                        {f'<div class="text-gray-600">in <span class="font-semibold">{method}()</span></div>' if method else ''}
                        {f'<div class="text-blue-600 font-semibold">{name}</div>' if name else ''}
                    </div>
                </div>
            """)
        
        html_parts.append('</div>')
        return ''.join(html_parts)
    
    def _get_severity_classes(self, severity: str) -> str:
        """
        Get Tailwind classes for severity badge.
        
        Args:
            severity: Severity level
            
        Returns:
            Tailwind CSS classes
        """
        severity = severity.upper()
        severity_styles = {
            "CRITICAL": "px-3 py-1 bg-red-900 text-white text-xs font-bold rounded",
            "HIGH": "px-3 py-1 bg-red-600 text-white text-xs font-bold rounded",
            "MEDIUM": "px-3 py-1 bg-orange-500 text-white text-xs font-bold rounded",
            "LOW": "px-3 py-1 bg-yellow-500 text-black text-xs font-bold rounded",
            "INFO": "px-3 py-1 bg-blue-500 text-white text-xs font-bold rounded"
        }
        return severity_styles.get(severity, "px-3 py-1 bg-gray-500 text-white text-xs font-bold rounded")
    
    def _get_result_classes(self, result: str) -> str:
        """
        Get CSS classes for assessment result.
        
        Args:
            result: Assessment result
            
        Returns:
            CSS classes
        """
        result = result.upper()
        result_styles = {
            "CONFIRMED": "text-red-600 font-bold text-sm",
            "NOT_EXPLOITABLE": "text-green-600 font-bold text-sm",
            "REFUSED": "text-amber-600 font-bold text-sm"
        }
        return result_styles.get(result, "text-gray-600 font-bold text-sm")