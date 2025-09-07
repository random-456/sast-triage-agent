"""
Main SAST Triage Agent using LangChain
"""

import os
import csv
import json
from typing import Dict, List, Any

from langchain_openai import ChatOpenAI
from langchain_core.messages import ToolMessage

from .config import CODEBASE_PATH, DEFAULT_CSV_FILE, DEFAULT_JSON_FILE, MAX_ANALYSIS_ITERATIONS
from .models import TriageDecision
from .tools import (
    read_file, search_in_files, list_directory, submit_triage_decision,
    parse_csv_findings, get_finding_details
)
from .logging_utils import LoggingManager


class SASTTriageAgent:
    """Main SAST Triage Agent using LangChain with custom LLM endpoint"""
    
    def __init__(
        self, 
        base_url: str = "http://localhost:4000",
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
            list_directory,  # Explore directory structure
            submit_triage_decision  # Submit final triage decision
        ]
        
        # Bind tools to the LLM
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        # Store model configuration for logging
        self.model_name = model_name
        self.temperature = temperature
        
        # Setup logging
        self.logger = LoggingManager(model_name, temperature)
        
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
        
        CRITICAL: Before reading any file with the read_file tool, CHECK THE CONVERSATION HISTORY FIRST.
        Do NOT re-read files you have already accessed - the complete file content is already available 
        in the conversation above. Re-reading the same file is wasteful and unnecessary.
        
        IMPORTANT: When you have completed your analysis and are ready to provide your final assessment,
        use the 'submit_triage_decision' tool with:
        - is_exploitable: true/false based on your analysis
        - confidence: your confidence level (0.0 to 1.0)
        - justification: detailed explanation of your decision
        """
    
    async def analyze_single_finding(self, finding_id: str, severity: str = None, update_csv: bool = True) -> TriageDecision:
        """
        Analyze a single finding and return triage decision.
        
        Args:
            finding_id: The finding ID to analyze
            severity: Original severity from Checkmarx (unused, kept for compatibility)
            update_csv: Whether to update CSV status (unused, kept for compatibility)
        
        Returns:
            TriageDecision with analysis results
        """
        # Start logging for this finding
        finding_log = self.logger.log_finding_start(finding_id)
        
        # Pre-load the complete finding details including dataflow
        finding_details = get_finding_details(finding_id)
        if 'error' in finding_details:
            decision = TriageDecision(
                findingId=finding_id,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Could not load finding details: {finding_details['error']}"
            )
            self.logger.log_finding_complete(finding_log, decision)
            return decision
        
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
        
        IMPORTANT: When you have completed your analysis and are ready to submit your decision,
        use the 'submit_triage_decision' tool with:
        - is_exploitable: true if the vulnerability is real and exploitable, false otherwise
        - confidence: your confidence level (0.0 to 1.0)
        - justification: detailed explanation of your decision
        
        Finding ID for reference: {finding_id}
        """
        
        try:
            # Build conversation with system prompt and user request
            messages = [
                ("system", self.system_prompt),
                ("human", input_prompt)
            ]
            
            # Log initial messages
            self.logger.log_message(finding_log, "system", self.system_prompt)
            self.logger.log_message(finding_log, "human", input_prompt)
            
            # Run the agent with tools - allow MORE iterations for deeper investigation
            max_iterations = MAX_ANALYSIS_ITERATIONS
            
            for iteration in range(max_iterations):
                print(f"  Iteration {iteration + 1}/{max_iterations}")
                
                # Get LLM response
                response = await self.llm_with_tools.ainvoke(messages)
                messages.append(response)
                
                # Log assistant response
                tool_calls_info = []
                if response.tool_calls:
                    tool_calls_info = [{"name": tc["name"], "args": tc["args"]} for tc in response.tool_calls]
                self.logger.log_message(finding_log, "assistant", response.content, tool_calls_info)
                
                # If LLM wants to use tools
                if response.tool_calls:
                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["args"]
                        
                        print(f"    Using tool: {tool_name}")
                        
                        # Check if this is the submit_triage_decision tool
                        if tool_name == "submit_triage_decision":
                            # Extract decision from tool arguments
                            try:
                                decision = TriageDecision(
                                    findingId=finding_id,
                                    assessment_result="CONFIRMED" if tool_args.get("is_exploitable") else "NOT_EXPLOITABLE",
                                    assessment_confidence=tool_args.get("confidence", 0.5),
                                    assessment_justification=tool_args.get("justification", "")
                                )
                                
                                # Log the decision
                                self.logger.log_finding_complete(finding_log, decision)
                                
                                print(f"  Decision submitted: {decision.assessment_result} (confidence: {decision.assessment_confidence:.2f})")
                                return decision
                                
                            except Exception as e:
                                print(f"  Error processing decision: {e}")
                                tool_result = {"error": f"Failed to process decision: {str(e)}"}
                        else:
                            # Execute other tools normally
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
                        
                        # Log tool result
                        self.logger.log_tool_result(finding_log, tool_name, tool_args, tool_result)
                        
                        # Add tool result to conversation
                        tool_message = ToolMessage(
                            content=str(tool_result),
                            tool_call_id=tool_call["id"]
                        )
                        messages.append(tool_message)
                else:
                    # No tool calls - check if we need to prompt for decision
                    if iteration == max_iterations - 1:
                        # Last iteration, prompt for decision
                        prompt = "Please use the submit_triage_decision tool to provide your final assessment."
                        messages.append(("human", prompt))
                        self.logger.log_message(finding_log, "human", prompt)
            
            # If we reach here, no decision was submitted via tool
            print(f"  Warning: No decision submitted after {max_iterations} iterations")
            
            # Return a timeout/refused decision
            decision = TriageDecision(
                findingId=finding_id,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Analysis did not complete within {max_iterations} iterations. Manual review required."
            )
            
            self.logger.log_finding_complete(finding_log, decision)
            return decision
        except Exception as e:
            print(f"Error analyzing finding {finding_id}: {str(e)}")
            decision = TriageDecision(
                findingId=finding_id,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Analysis failed due to error: {str(e)}. Manual review required."
            )
            self.logger.log_finding_complete(finding_log, decision)
            return decision
    
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
            
            try:
                decision = await self.analyze_single_finding(
                    finding['findingId'],
                    finding['severity'],
                    update_csv=False
                )
                
                result_dict = decision.model_dump()
                triage_results.append(result_dict)
                
                # Save result
                self.save_incremental_result(result_dict)
                
                # Mark as triaged after analysis
                self.update_csv_status(finding['findingId'], csv_path)
                
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
                
                # Mark as triaged even for errors (so they don't retry indefinitely)
                self.update_csv_status(finding['findingId'], csv_path)
        
        # Save results (findings_assessment.json)
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