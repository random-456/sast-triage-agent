"""
SAST Triage Agent using LangChain and Gemini
Analyzes Checkmarx findings and provides automated triage decisions
"""

import os
import csv
import json
import asyncio
from typing import Dict, List, Optional

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from pydantic import BaseModel, Field


# Configuration
CODEBASE_PATH = "./codebase"
FINDINGS_PATH = "findings"
DEFAULT_CSV_FILE = f"{FINDINGS_PATH}/triage_list.csv"
DEFAULT_JSON_FILE = f"{FINDINGS_PATH}/findings_details.json"


class TriageDecision(BaseModel):
    """Structured output for triage decisions matching Checkmarx format"""
    findingId: str = Field(description="Unique identifier for the finding")
    assessment_result: str = Field(description="CONFIRMED, NOT_EXPLOITABLE, or REFUSED")
    assessment_confidence: float = Field(description="Confidence score between 0 and 1")
    assessment_justification: str = Field(description="Detailed justification for the decision")


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






class SASTTriageAgent:
    """Main SAST Triage Agent using LangChain with custom LLM endpoint"""
    
    def __init__(
        self, 
        base_url: str = "http://localhost:4000",  # LiteLLM proxy URL
        model_name: str = "gemini-2.5-pro", 
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
            read_file,  # Read entire files
            search_in_files,  # Search patterns across codebase
            list_directory  # Explore directory structure
        ]
        
        # Bind tools to the LLM
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        # System prompt for the security analyst
        self.system_prompt = """You are an experienced senior security analyst evaluating SAST findings from Checkmarx.
        
        Your approach should be investigative and thorough:
        - Start by understanding what the vulnerability claim is
        - Investigate the code to see if it's truly exploitable
        - Look for evidence, not just follow procedures
        - Consider real-world exploitability, not just theoretical risks
        
        Be skeptical but fair:
        - Don't assume sanitization exists without seeing it
        - Don't assume it's safe just because it looks okay
        - But also don't mark everything as vulnerable without evidence
        
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
        # Pre-load the complete finding details including dataflow
        finding_details = get_finding_details(finding_id)
        if 'error' in finding_details:
            return TriageDecision(
                findingId=finding_id,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Could not load finding details: {finding_details['error']}"
            )
        
        # Create comprehensive initial context
        input_prompt = f"""
        Here is a SAST finding from Checkmarx. Investigate the codebase and determine if it's truly exploitable.
        
        FINDING DETAILS:
        {json.dumps(finding_details, indent=2)}
        
        CODEBASE ACCESS:
        You can explore the codebase however you want using these tools:
        - read_file: Read any file completely
        - search_in_files: Search for patterns across all files
        - list_directory: Explore the project structure
        
        INVESTIGATION:
        Investigate however you think is best. You might want to:
        - Read the files mentioned in the dataflow
        - Look for sanitization or validation functions
        - Understand how the application works
        - Search for similar patterns or security controls
        - Explore related files or directories
        
        Take as much time as you need. Read whatever files you think are relevant.
        The goal is to understand if this vulnerability is real and exploitable.
        
        After your investigation, provide your final assessment as a JSON object.
        The LAST thing in your response must be this JSON (you can explain your analysis before it):
        
        {{
            "findingId": "{finding_id}",
            "assessment_result": "CONFIRMED",
            "assessment_confidence": 0.85,
            "assessment_justification": "Based on my analysis, this is a true positive XSS vulnerability because user input flows to innerHTML without sanitization..."
        }}
        
        Requirements:
        - assessment_result: "CONFIRMED" or "NOT_EXPLOITABLE" or "REFUSED"
        - assessment_confidence: 0.0 to 1.0
        - assessment_justification: Your analysis summary
        - Put the JSON at the END of your response
        """
        
        try:
            # Build conversation with system prompt and user request
            messages = [
                ("system", self.system_prompt),
                ("human", input_prompt)
            ]
            
            # Run the agent with tools - allow MORE iterations for deeper investigation
            max_iterations = 25
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
                    # No more tool calls, check if we have valid JSON
                    output = response.content
                    
                    # Quick check if response contains valid JSON
                    if '{' in output and 'findingId' in output:
                        break
                    
                    # If not, ask for JSON formatting
                    messages.append(("human", f"Please provide your final assessment as the JSON format requested, with findingId='{finding_id}'."))
                    retry_response = await self.llm_with_tools.ainvoke(messages)
                    messages.append(retry_response)
                    break
            
            # Get the final response content
            output = messages[-1].content if messages else "{}"
            
            # Try to extract JSON from the output
            import re
            
            # Try to find JSON at the end of the response
            # Look for the last JSON-like structure in the output
            json_patterns = [
                r'\{[^{}]*"findingId"[^{}]*"assessment_result"[^{}]*"assessment_confidence"[^{}]*"assessment_justification"[^{}]*\}',
                r'\{\s*"findingId".*?"assessment_justification".*?\}',
                r'\{[^}]*"findingId"[^}]*\}(?!.*\{[^}]*"findingId")'  # Last JSON with findingId
            ]
            
            for pattern in json_patterns:
                matches = re.findall(pattern, output, re.DOTALL)
                if matches:
                    # Take the last match (should be at the end)
                    try:
                        decision_dict = json.loads(matches[-1])
                        if 'findingId' in decision_dict:
                            return TriageDecision(**decision_dict)
                    except json.JSONDecodeError:
                        continue
            
            # If no JSON found, try to extract from the text more intelligently
            # Look for the actual analysis content
            print(f"  Warning: Could not extract JSON from response. Full output:\n{output[:500]}...")
            
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
        """Update the triaged status in CSV file."""
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
    
    def save_incremental_result(self, result: Dict):
        """Save individual result immediately to findings_assessment.json."""
        output_file = 'findings_assessment.json'
        try:
            # Load existing results if file exists
            existing_results = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    existing_results = json.load(f)
            
            # Add new result (or update if finding already exists)
            finding_id = result['findingId']
            updated = False
            for i, existing in enumerate(existing_results):
                if existing['findingId'] == finding_id:
                    existing_results[i] = result
                    updated = True
                    break
            
            if not updated:
                existing_results.append(result)
            
            # Save back to file
            with open(output_file, 'w') as f:
                json.dump(existing_results, f, indent=2)
            
            print(f"  Saved result to {output_file}")
        except Exception as e:
            print(f"  Warning: Could not save incremental result: {str(e)}")
    
    def get_pending_findings(self, csv_path: str) -> List[Dict]:
        """Get findings that haven't been triaged yet (triaged = 'no')."""
        try:
            findings = parse_csv_findings(csv_path)
            if findings and 'error' not in findings[0]:
                # Only return findings not yet triaged
                pending = [f for f in findings if f.get('triaged', '').lower() == 'no']
                return pending
            return []
        except Exception as e:
            print(f"Error getting pending findings: {str(e)}")
            return []
    
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
        
        # Get only pending findings (skip already triaged)
        findings = self.get_pending_findings(csv_path)
        
        if not findings:
            print("No pending findings to triage (all marked as 'yes' in CSV)")
            # Load existing results if any
            if os.path.exists('findings_assessment.json'):
                with open('findings_assessment.json', 'r') as f:
                    return json.load(f)
            return []
        
        print(f"Found {len(findings)} pending findings to triage")
        
        # Analyze each pending finding
        triage_results = []
        for i, finding in enumerate(findings):
            print(f"\nAnalyzing finding {i+1}/{len(findings)}: {finding['findingId']}")
            
            # Mark as triaged IMMEDIATELY when starting
            self.update_csv_status(finding['findingId'], csv_path)
            
            try:
                decision = await self.analyze_single_finding(
                    finding['findingId'],
                    finding['severity'],
                    update_csv=False  # Already updated above
                )
                
                result_dict = decision.dict()
                triage_results.append(result_dict)
                
                # Save result immediately
                self.save_incremental_result(result_dict)
                
                # Print summary
                print(f"  Result: {decision.assessment_result}")
                print(f"  Confidence: {decision.assessment_confidence:.2f}")
                print(f"  Justification: {decision.assessment_justification[:100]}...")
                
            except Exception as e:
                print(f"  Error analyzing {finding['findingId']}: {str(e)}")
                # Save error result
                error_result = {
                    'findingId': finding['findingId'],
                    'assessment_result': 'REFUSED',
                    'assessment_confidence': 0.0,
                    'assessment_justification': f'Analysis failed: {str(e)}'
                }
                triage_results.append(error_result)
                self.save_incremental_result(error_result)
        
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
        model_name="gemini-2.5-pro",
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