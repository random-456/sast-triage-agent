"""
SAST Triage Agent using LangChain and Gemini
Analyzes Checkmarx findings and provides automated triage decisions
"""

import os
import csv
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from pydantic import BaseModel, Field
from typing_extensions import TypedDict


# Configuration
CODEBASE_PATH = "./codebase"
FINDINGS_PATH = "findings"
DEFAULT_CSV_FILE = f"{FINDINGS_PATH}/triage_list.csv"
DEFAULT_JSON_FILE = f"{FINDINGS_PATH}/findings_details.json"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TriageStatus(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class DataflowNode(BaseModel):
    """Represents a single node in the dataflow chain"""
    column: str
    fileName: str
    fullName: str
    length: int
    line: str
    methodLine: int
    method: str
    name: str
    nodeID: int
    domType: str


class Finding(BaseModel):
    """Represents a Checkmarx finding"""
    findingId: str
    category: str
    cweID: int
    languageName: str
    queryName: str
    severity: Severity
    dataflow: List[Dict]


class TriageDecision(BaseModel):
    """Structured output for triage decisions matching Checkmarx format"""
    findingId: str = Field(description="Unique identifier for the finding")
    assessment_result: str = Field(description="CONFIRMED, NOT_EXPLOITABLE, or REFUSED")
    assessment_confidence: float = Field(description="Confidence score between 0 and 1")
    assessment_justification: str = Field(description="Detailed justification for the decision")


class TriageState(TypedDict):
    """State management for the triage workflow"""
    csv_path: str
    json_path: str
    codebase_path: str
    findings_list: List[Dict]
    findings_details: List[Dict]
    current_finding: Optional[Dict]
    current_index: int
    triage_results: List[Dict]
    analysis_complete: bool
    error_log: List[str]


# Tool Definitions
@tool
def parse_csv_findings(file_path: str = DEFAULT_CSV_FILE) -> List[Dict]:
    """
    Parse the CSV file containing SAST findings list.
    
    Args:
        file_path: Path to the CSV file with findingId, severity, triaged columns
    
    Returns:
        List of finding records from CSV
    """
    try:
        findings = []
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['triaged'].lower() == 'no':
                    findings.append({
                        'findingId': row['findingId'],
                        'severity': row['severity'],
                        'triaged': row['triaged']
                    })
        return findings
    except Exception as e:
        return [{"error": f"Failed to parse CSV: {str(e)}"}]


@tool
def get_finding_details(finding_id: str, json_path: str = DEFAULT_JSON_FILE) -> Dict:
    """
    Get detailed information for a specific finding from JSON file.
    
    Args:
        finding_id: The finding ID to look up
        json_path: Path to the JSON file with detailed findings
    
    Returns:
        Detailed finding information including dataflow
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            all_findings = json.load(f)
        
        for finding in all_findings:
            if finding['findingId'] == finding_id:
                return finding
        
        return {"error": f"Finding {finding_id} not found in details"}
    except Exception as e:
        return {"error": f"Failed to get finding details: {str(e)}"}


@tool
def read_file(file_path: str) -> Dict:
    """
    Read an entire file from the codebase.
    
    Args:
        file_path: Path to the file relative to codebase
    
    Returns:
        Complete file contents with line numbers
    """
    try:
        full_path = os.path.join(CODEBASE_PATH, file_path.lstrip('/'))
        
        if not os.path.exists(full_path):
            return {"error": f"File not found: {full_path}"}
        
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Limit large files to prevent overwhelming the LLM
        max_lines = 500
        if len(lines) > max_lines:
            truncated = True
            lines = lines[:max_lines]
        else:
            truncated = False
        
        result = {
            'file': file_path,
            'total_lines': len(lines),
            'truncated': truncated,
            'content': []
        }
        
        for i, line in enumerate(lines):
            result['content'].append(f"{i+1:5}: {line.rstrip()}")
        
        return result
    except Exception as e:
        return {"error": f"Failed to read file: {str(e)}"}


@tool
def search_in_files(pattern: str, file_extension: str) -> Dict:
    """
    Search for a pattern in files within the codebase.
    
    Args:
        pattern: String or regex to search for
        file_extension: File extension to search (e.g. "py", "js", "ts")
    
    Returns:
        Search results with file paths and matching lines
    """
    import re
    import glob
    
    try:
        results = []
        file_pattern = f"*.{file_extension}"
        search_path = os.path.join(CODEBASE_PATH, "**", file_pattern)
        files = glob.glob(search_path, recursive=True)
        
        pattern_re = re.compile(pattern, re.IGNORECASE)
        max_results = 30  # Fixed limit to avoid overwhelming
        
        for file_path in files[:50]:  # Limit files to search
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if pattern_re.search(line):
                            rel_path = os.path.relpath(file_path, CODEBASE_PATH)
                            results.append({
                                'file': rel_path,
                                'line': i + 1,
                                'content': line.strip()
                            })
                            if len(results) >= max_results:
                                break
                if len(results) >= max_results:
                    break
            except:
                continue
        
        return {
            'pattern': pattern,
            'file_extension': file_extension,
            'matches_found': len(results),
            'results': results
        }
    except Exception as e:
        return {"error": f"Search failed: {str(e)}"}


@tool
def list_directory(directory_path: str) -> Dict:
    """
    List files and directories in a given path within the codebase.
    
    Args:
        directory_path: Path relative to codebase (use "." for root)
    
    Returns:
        List of files and directories
    """
    try:
        if directory_path == ".":
            full_path = CODEBASE_PATH
        else:
            full_path = os.path.join(CODEBASE_PATH, directory_path.lstrip('/'))
        
        if not os.path.exists(full_path):
            return {"error": f"Directory not found: {full_path}"}
        
        items = []
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            items.append({
                'name': item,
                'type': 'directory' if os.path.isdir(item_path) else 'file',
                'size': os.path.getsize(item_path) if os.path.isfile(item_path) else None
            })
        
        return {
            'directory': directory_path,
            'total_items': len(items),
            'items': sorted(items, key=lambda x: (x['type'], x['name']))
        }
    except Exception as e:
        return {"error": f"Failed to list directory: {str(e)}"}


@tool
def analyze_code_location(file_path: str, line_number: int) -> Dict:
    """
    Analyze code at a specific location with surrounding context.
    
    Args:
        file_path: Path to the source file relative to codebase
        line_number: Line number to analyze
    
    Returns:
        Code context and analysis information
    """
    try:
        full_path = os.path.join(CODEBASE_PATH, file_path.lstrip('/'))
        
        if not os.path.exists(full_path):
            return {"error": f"File not found: {full_path}"}
        
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        context_lines = 15  # Fixed context
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context = {
            'file': file_path,
            'target_line': line_number,
            'total_lines': len(lines),
            'context_start': start + 1,
            'context_end': end,
            'code': []
        }
        
        for i in range(start, end):
            context['code'].append({
                'line_number': i + 1,
                'content': lines[i].rstrip(),
                'is_target': i + 1 == line_number
            })
        
        return context
    except Exception as e:
        return {"error": f"Failed to analyze code: {str(e)}"}


@tool
def trace_dataflow(dataflow_nodes: str) -> Dict:
    """
    Trace the complete dataflow path from source to sink.
    
    Args:
        dataflow_nodes: JSON string of dataflow nodes
    
    Returns:
        Analysis of the dataflow path including taint propagation
    """
    try:
        nodes = json.loads(dataflow_nodes) if isinstance(dataflow_nodes, str) else dataflow_nodes
        
        if not nodes:
            return {"error": "No dataflow nodes provided"}
        
        analysis = {
            'total_nodes': len(nodes),
            'source': nodes[0] if nodes else None,
            'sink': nodes[-1] if nodes else None,
            'path_summary': [],
            'user_input_detected': False,
            'sanitization_detected': False
        }
        
        for i, node in enumerate(nodes):
            node_summary = {
                'position': i + 1,
                'file': node.get('fileName', ''),
                'method': node.get('method', ''),
                'line': node.get('line', ''),
                'type': node.get('domType', ''),
                'name': node.get('name', '')
            }
            
            # Check for user input sources
            if any(keyword in str(node).lower() for keyword in ['request', 'param', 'query', 'input', 'user']):
                analysis['user_input_detected'] = True
                node_summary['is_source'] = True
            
            # Check for sanitization
            if any(keyword in str(node).lower() for keyword in ['sanitize', 'escape', 'encode', 'validate', 'clean']):
                analysis['sanitization_detected'] = True
                node_summary['is_sanitizer'] = True
            
            analysis['path_summary'].append(node_summary)
        
        return analysis
    except Exception as e:
        return {"error": f"Failed to trace dataflow: {str(e)}"}


@tool
def examine_code_patterns(code_content: str, focus_area: str) -> Dict:
    """
    Examine code for specific patterns or security-relevant features.
    
    Args:
        code_content: Code content to analyze
        focus_area: What to focus on (e.g. "security_controls", "input_handling", "database_queries")
    
    Returns:
        Analysis of patterns found in the code
    """
    try:
        lines = code_content.split('\n')
        patterns_found = []
        
        # Generic pattern detection based on focus area
        focus_lower = focus_area.lower()
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Look for patterns based on focus area
            if 'security' in focus_lower or 'control' in focus_lower:
                security_keywords = ['sanitize', 'escape', 'encode', 'validate', 'clean', 'filter', 'auth', 'permission', 'csrf', 'secure']
                for keyword in security_keywords:
                    if keyword in line_lower:
                        patterns_found.append({
                            'line': i + 1,
                            'pattern': keyword,
                            'context': line.strip()
                        })
            
            elif 'input' in focus_lower:
                input_keywords = ['request', 'param', 'query', 'body', 'form', 'user', 'input']
                for keyword in input_keywords:
                    if keyword in line_lower:
                        patterns_found.append({
                            'line': i + 1,
                            'pattern': keyword,
                            'context': line.strip()
                        })
            
            elif 'database' in focus_lower or 'sql' in focus_lower:
                db_keywords = ['query', 'execute', 'select', 'insert', 'update', 'delete', 'sql', 'prepare']
                for keyword in db_keywords:
                    if keyword in line_lower:
                        patterns_found.append({
                            'line': i + 1,
                            'pattern': keyword,
                            'context': line.strip()
                        })
        
        return {
            'focus_area': focus_area,
            'patterns_found': patterns_found,
            'pattern_count': len(patterns_found),
            'analysis_summary': f"Found {len(patterns_found)} relevant patterns related to {focus_area}"
        }
    except Exception as e:
        return {"error": f"Pattern analysis failed: {str(e)}"}




class SASTTriageAgent:
    """Main SAST Triage Agent using LangChain with custom LLM endpoint"""
    
    def __init__(
        self, 
        base_url: str = "http://localhost:4000",  # LiteLLM proxy URL
        model_name: str = "gemini-2.5-flash", 
        api_key: str = "dummy-key",
        temperature: float = 0.1
    ):
        """
        Initialize the SAST Triage Agent.
        
        Args:
            base_url: Base URL for the OpenAI-compatible endpoint
            model_name: Model name as configured in your proxy
            api_key: API key (can be dummy for local proxies)
            temperature: Model temperature for consistency
        """
        self.llm = ChatOpenAI(
            base_url=base_url,
            model=model_name,
            api_key=api_key,
            temperature=temperature,
            max_retries=3
        )
        
        self.tools = [
            parse_csv_findings,
            get_finding_details,
            read_file,  # Read entire files
            search_in_files,  # Search patterns across codebase
            list_directory,  # Explore directory structure
            analyze_code_location,  # Quick code context
            trace_dataflow,
            examine_code_patterns  # Generic pattern analysis tool
        ]
        
        # Bind tools to the LLM
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        # System prompt for the security analyst
        self.system_prompt = """You are an experienced senior cyber security analyst. Your task is to evaluate SAST findings reported by Checkmarx One and decide if they are true or false positives.
        
        CRITICAL RULES:
        1. Analyze one finding at a time thoroughly by checking the details and analyzing the source code
        2. Retrace the finding and analyze if it is valid (true positive) or not (false positive) by systematically understanding the source code
        3. NEVER modify any files in the codebase - you are only analyzing
        4. Your decisions must be correct - only make decisions if you are confident enough after analyzing everything related
        
        For each finding assessment, you must provide:
        - assessment_result: "CONFIRMED" (true positive), "NOT_EXPLOITABLE" (false positive), or "REFUSED" (insufficient information)
        - assessment_confidence: Score between 0 and 1 (where 1 is maximum confidence)
        - assessment_justification: Detailed justification for your decision
        
        Your analysis must be thorough and consider:
        a) Component Context: The code's role, environment, and interactions within the system
        b) Data Flow & Trust: Trace data origins and movement, identifying trust boundaries and input sources (trusted vs. untrusted)
        c) Security Controls: Assess existing mitigations (validation, authentication, authorization) and their effectiveness
        d) Exploitation Potential: Consider how an attacker might leverage the finding, including indirect or chained attack vectors
        
        IMPORTANT CONSIDERATIONS:
        - If detected finding is likely not true-positive but there's another closely linked vulnerability in the same area, report as CONFIRMED with explanation
        - Even if exploitation potential is relatively low (but not zero), report as CONFIRMED with details
        - Consider privileged attacker scenarios in your analyses
        - Analyze each finding separately without referring to other findings
        - Focus on HIGH QUALITY assessment - think hard and perform as many analysis steps as needed
        
        Use ALL available tools to:
        1. Get finding details from JSON
        2. Trace complete dataflow from source to sink
        3. Analyze code at each critical point in dataflow
        4. Check for vulnerability patterns and existing mitigations
        5. Make informed decision based on comprehensive analysis
        """
    
    async def analyze_single_finding(self, finding_id: str, severity: str, update_csv: bool = True) -> TriageDecision:
        """
        Analyze a single finding and return triage decision.
        
        Args:
            finding_id: The finding ID to analyze
            severity: Original severity from Checkmarx
        
        Returns:
            TriageDecision with analysis results
        """
        input_prompt = f"""
        Analyze Checkmarx finding {finding_id} with severity {severity}.
        
        MANDATORY ANALYSIS STEPS:
        1. Use get_finding_details to get the complete finding information for finding_id: {finding_id}
        2. Use trace_dataflow to analyze the complete dataflow path
        3. For EACH node in the dataflow (especially source, intermediate nodes, and sink):
           - Use analyze_code_location to examine the actual code
           - Use examine_code_patterns to look for security controls or vulnerability patterns
        4. Trace data origins and movement across trust boundaries
        5. Assess existing security controls and their effectiveness
        6. Consider exploitation scenarios including privileged attackers
        
        CRITICAL: You MUST end your response with EXACTLY this JSON format (no additional text after):

        {{
            "findingId": "{finding_id}",
            "assessment_result": "CONFIRMED",
            "assessment_confidence": 0.85,
            "assessment_justification": "Your detailed analysis here"
        }}

        RULES FOR JSON RESPONSE:
        - assessment_result: Must be exactly "CONFIRMED", "NOT_EXPLOITABLE", or "REFUSED"
        - assessment_confidence: Number between 0.0 and 1.0
        - assessment_justification: Detailed explanation of your analysis and decision
        - NO text after the JSON block
        - NO markdown formatting around JSON
        - NO explanation before or after JSON
        """
        
        try:
            # Build conversation with system prompt and user request
            messages = [
                ("system", self.system_prompt),
                ("human", input_prompt)
            ]
            
            # Run the agent with tools - allow multiple iterations
            max_iterations = 15
            for iteration in range(max_iterations):
                print(f"  Iteration {iteration + 1}/{max_iterations}")
                
                # Get LLM response
                response = await self.llm_with_tools.ainvoke(messages)
                messages.append(response)
                
                # If LLM wants to use tools
                if response.tool_calls:
                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["args"]
                        
                        print(f"    Using tool: {tool_name}")
                        
                        # Find and execute the tool
                        tool_result = None
                        for t in self.tools:
                            if t.name == tool_name:
                                try:
                                    tool_result = t.invoke(tool_args)
                                except Exception as e:
                                    tool_result = {"error": str(e)}
                                break
                        
                        if tool_result is None:
                            tool_result = {"error": f"Tool {tool_name} not found"}
                        
                        # Add tool result to conversation
                        tool_message = ToolMessage(
                            content=str(tool_result),
                            tool_call_id=tool_call["id"]
                        )
                        messages.append(tool_message)
                else:
                    # No more tool calls, we have the final answer
                    break
            
            # Get the final response content
            output = messages[-1].content if messages else "{}"
            
            # Try to extract JSON from the output
            import re
            
            # Try multiple JSON extraction patterns
            json_patterns = [
                r'\{[^{}]*"findingId"[^{}]*\}',  # Single-line JSON
                r'\{\s*"findingId".*?\}',        # Multi-line JSON
                r'\{.*?"assessment_result".*?\}' # Look for key field
            ]
            
            for pattern in json_patterns:
                json_match = re.search(pattern, output, re.DOTALL)
                if json_match:
                    try:
                        decision_dict = json.loads(json_match.group())
                        if 'findingId' in decision_dict:  # Validate it has required field
                            return TriageDecision(**decision_dict)
                    except json.JSONDecodeError:
                        continue
            
            # If no valid JSON, try to extract key information from the text
            result = "REFUSED"
            confidence = 0.3
            
            # Look for assessment patterns in the text
            if "CONFIRMED" in output.upper():
                result = "CONFIRMED"
                confidence = 0.7
            elif "NOT_EXPLOITABLE" in output.upper() or "FALSE POSITIVE" in output.upper():
                result = "NOT_EXPLOITABLE"
                confidence = 0.7
            
            # Extract any justification text
            justification_patterns = [
                r"justification[:\s]+([^\n]+)",
                r"reason[:\s]+([^\n]+)",
                r"because[:\s]+([^\n]+)"
            ]
            
            justification = "Analysis completed but structured output was not properly formatted."
            for pattern in justification_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    justification = match.group(1).strip()
                    break
            
            # Add context about what was analyzed
            if "tool:" in output.lower():
                justification += f" Tools were used during analysis. Full output: {output[:500]}..."
            
            return TriageDecision(
                findingId=finding_id,
                assessment_result=result,
                assessment_confidence=confidence,
                assessment_justification=justification
            )
        except Exception as e:
            print(f"Error analyzing finding {finding_id}: {str(e)}")
            return TriageDecision(
                findingId=finding_id,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Analysis failed due to error: {str(e)}. Manual review required."
            )
    
    def update_csv_status(self, finding_id: str, csv_path: str = DEFAULT_CSV_FILE):
        """Update the triaged status in CSV file after analyzing a finding."""
        try:
            # Read CSV
            rows = []
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                for row in reader:
                    if row['findingId'] == finding_id:
                        row['triaged'] = 'yes'
                    rows.append(row)
            
            # Write updated CSV
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            
            print(f"  Updated CSV: marked {finding_id} as triaged")
        except Exception as e:
            print(f"  Warning: Could not update CSV for {finding_id}: {str(e)}")
    
    async def process_all_findings(
        self,
        csv_path: str = DEFAULT_CSV_FILE,
        json_path: str = DEFAULT_JSON_FILE
    ) -> Dict:
        """
        Process all findings from CSV and generate triage report.
        
        Args:
            csv_path: Path to CSV file with findings list
            json_path: Path to JSON file with finding details
            output_path: Path to save the triage results
        
        Returns:
            Complete triage report
        """
        print(f"Starting SAST triage analysis...")
        print(f"CSV: {csv_path}")
        print(f"JSON: {json_path}")
        print(f"Codebase: {CODEBASE_PATH}")
        
        # Parse CSV to get findings list
        findings = parse_csv_findings(csv_path)
        
        if not findings or 'error' in findings[0]:
            return {
                "error": "Failed to parse CSV findings",
                "details": findings
            }
        
        print(f"Found {len(findings)} findings to triage")
        
        # Analyze each finding
        triage_results = []
        for i, finding in enumerate(findings):
            print(f"\nAnalyzing finding {i+1}/{len(findings)}: {finding['findingId']}")
            
            decision = await self.analyze_single_finding(
                finding['findingId'],
                finding['severity'],
                update_csv=False  # We'll update after successful analysis
            )
            
            # Update CSV immediately after each successful finding
            self.update_csv_status(finding['findingId'], csv_path)
            
            triage_results.append(decision.dict())
            
            # Print summary
            print(f"  Result: {decision.assessment_result}")
            print(f"  Confidence: {decision.assessment_confidence:.2f}")
            print(f"  Justification: {decision.assessment_justification[:100]}...")
        
        # Save results in requested format (findings_assessment.json)
        with open('findings_assessment.json', 'w') as f:
            json.dump(triage_results, f, indent=2)
        
        # Generate summary for display
        summary = {
            'total_findings': len(triage_results),
            'confirmed': sum(1 for r in triage_results if r['assessment_result'] == 'CONFIRMED'),
            'not_exploitable': sum(1 for r in triage_results if r['assessment_result'] == 'NOT_EXPLOITABLE'),
            'refused': sum(1 for r in triage_results if r['assessment_result'] == 'REFUSED'),
            'high_confidence': sum(1 for r in triage_results if r['assessment_confidence'] >= 0.8)
        }
        
        print(f"\nTriage complete! Results saved to findings_assessment.json")
        print(f"Summary:")
        print(f"  CONFIRMED: {summary['confirmed']}")
        print(f"  NOT_EXPLOITABLE: {summary['not_exploitable']}")
        print(f"  REFUSED: {summary['refused']}")
        print(f"  High Confidence (>=0.8): {summary['high_confidence']}/{summary['total_findings']}")
        
        # Check for code mismatch
        if summary['refused'] == summary['total_findings']:
            error_result = [{"error": "Code base and findings report do not match."}]
            with open('findings_assessment.json', 'w') as f:
                json.dump(error_result, f, indent=2)
            return error_result
        
        return triage_results




# Main execution
async def main():
    """Main entry point for the SAST triage agent"""
    
    # Initialize the agent
    agent = SASTTriageAgent(
        model_name="gemini-2.5-flash",
        temperature=0.1
    )
    
    # Process findings
    results = await agent.process_all_findings(
        csv_path=DEFAULT_CSV_FILE,
        json_path=DEFAULT_JSON_FILE
    )
    
    return results


if __name__ == "__main__":
    # Run the agent
    asyncio.run(main())