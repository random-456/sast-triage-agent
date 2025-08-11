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
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import JsonOutputParser
from langchain.agents import create_structured_chat_agent, AgentExecutor
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from typing_extensions import TypedDict


# Configuration
CODEBASE_PATH = "/codebase"
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
def analyze_code_location(file_path: str, line_number: int, context_lines: int = 15) -> Dict:
    """
    Analyze code at a specific location with surrounding context.
    
    Args:
        file_path: Path to the source file relative to codebase
        line_number: Line number to analyze
        context_lines: Number of lines before and after to include
    
    Returns:
        Code context and analysis information
    """
    try:
        full_path = os.path.join(CODEBASE_PATH, file_path.lstrip('/'))
        
        if not os.path.exists(full_path):
            return {"error": f"File not found: {full_path}"}
        
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
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
def check_for_sanitization(code_snippet: str) -> Dict:
    """
    Check if code contains common sanitization or validation functions.
    
    Args:
        code_snippet: Code to analyze
    
    Returns:
        Information about potential security controls found
    """
    sanitization_keywords = [
        'sanitize', 'escape', 'encode', 'validate', 'clean',
        'filter', 'strip', 'purify', 'whitelist', 'blacklist',
        'parameterized', 'prepared', 'bound', 'safe'
    ]
    
    code_lower = code_snippet.lower()
    found_controls = []
    
    for keyword in sanitization_keywords:
        if keyword in code_lower:
            # Find the actual line containing the keyword
            for line in code_snippet.split('\n'):
                if keyword in line.lower():
                    found_controls.append({
                        'keyword': keyword,
                        'context': line.strip()[:100]  # First 100 chars of the line
                    })
                    break
    
    return {
        'has_sanitization': len(found_controls) > 0,
        'controls_found': found_controls,
        'control_count': len(found_controls)
    }




class SASTTriageAgent:
    """Main SAST Triage Agent using LangChain with custom LLM endpoint"""
    
    def __init__(
        self, 
        base_url: str = "http://localhost:4000",  # Your LiteLLM proxy URL
        model_name: str = "gemini-2.0-flash-exp", 
        api_key: str = "dummy-key",  # LiteLLM often accepts any key
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
            analyze_code_location,
            trace_dataflow,
            check_for_sanitization
        ]
        
        self.memory = MemorySaver()
        self.output_parser = JsonOutputParser()
        
        # Create the main triage prompt
        self.triage_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an experienced senior cyber security analyst. Your task is to evaluate SAST findings reported by Checkmarx One and decide if they are true or false positives.
            
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
            """),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])
        
        # Create the agent
        self.agent = create_structured_chat_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=self.triage_prompt
        )
        
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            max_iterations=15,  # Allow thorough analysis
            handle_parsing_errors=True,
            return_intermediate_steps=True
        )
    
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
           - Use check_for_sanitization to identify any security controls
        4. Trace data origins and movement across trust boundaries
        5. Assess existing security controls and their effectiveness
        6. Consider exploitation scenarios including privileged attackers
        
        Make your assessment and provide your decision in EXACTLY this JSON format:
        {{
            "findingId": "{finding_id}",
            "assessment_result": "CONFIRMED or NOT_EXPLOITABLE or REFUSED",
            "assessment_confidence": 0.0-1.0,
            "assessment_justification": "Detailed justification including: (1) What the vulnerability is, (2) How it could be exploited, (3) Why you made this decision, (4) Any mitigating factors found"
        }}
        
        Remember:
        - CONFIRMED: True positive vulnerability (even if exploitation difficulty is high)
        - NOT_EXPLOITABLE: False positive with strong evidence of mitigation
        - REFUSED: Insufficient information to make confident decision
        - Your confidence must reflect the thoroughness of your analysis
        - Justification must be detailed and reference specific code locations analyzed
        """
        
        try:
            result = await self.agent_executor.ainvoke({
                "input": input_prompt,
                "chat_history": []
            })
            
            # Parse the agent's response
            output = result.get("output", "{}")
            
            # Try to extract JSON from the output
            import re
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                decision_dict = json.loads(json_match.group())
                return TriageDecision(**decision_dict)
            else:
                # Fallback decision if parsing fails
                return TriageDecision(
                    findingId=finding_id,
                    assessment_result="REFUSED",
                    assessment_confidence=0.3,
                    assessment_justification="Analysis incomplete - manual review required. The agent could not extract a structured decision from the analysis."
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


# LangGraph Implementation for Complex Workflows
def create_langgraph_workflow():
    """
    Create a LangGraph workflow for parallel finding analysis.
    """
    
    def parse_findings_node(state: TriageState) -> TriageState:
        """Parse CSV and JSON findings"""
        findings = parse_csv_findings(state['csv_path'])
        state['findings_list'] = findings
        
        # Load all finding details
        with open(state['json_path'], 'r') as f:
            state['findings_details'] = json.load(f)
        
        return state
    
    def analyze_finding_node(state: TriageState) -> TriageState:
        """Analyze current finding"""
        if state['current_index'] >= len(state['findings_list']):
            state['analysis_complete'] = True
            return state
        
        current = state['findings_list'][state['current_index']]
        
        # Get detailed analysis
        details = get_finding_details(current['findingId'], state['json_path'])
        
        # Analyze dataflow
        if 'dataflow' in details:
            dataflow_analysis = trace_dataflow(json.dumps(details['dataflow']))
            
            # Analyze key code locations
            code_analyses = []
            for node in details['dataflow'][:3]:  # Analyze first 3 nodes
                code_context = analyze_code_location(
                    node['fileName'],
                    int(node['line'])
                )
                code_analyses.append(code_context)
        
        # Store results
        state['current_finding'] = {
            'finding': current,
            'details': details,
            'analysis': {
                'dataflow': dataflow_analysis if 'dataflow' in details else {},
                'code_contexts': code_analyses if 'dataflow' in details else []
            }
        }
        
        return state
    
    def make_decision_node(state: TriageState) -> TriageState:
        """Make triage decision for current finding"""
        if not state['current_finding']:
            return state
        
        # Decision logic based on analysis
        finding = state['current_finding']
        confidence = 0.7  # Base confidence
        
        # Adjust confidence based on analysis
        if finding['analysis']['dataflow'].get('sanitization_detected'):
            confidence -= 0.3
            status = "false_positive"
        elif finding['analysis']['dataflow'].get('user_input_detected'):
            confidence += 0.2
            status = "true_positive"
        else:
            status = "needs_review"
        
        decision = {
            'finding_id': finding['finding']['findingId'],
            'triage_status': status,
            'confidence_score': min(max(confidence, 0.0), 1.0),
            'justification': "Automated analysis based on dataflow and code context"
        }
        
        state['triage_results'].append(decision)
        state['current_index'] += 1
        
        return state
    
    def should_continue(state: TriageState) -> str:
        """Determine if analysis should continue"""
        if state['analysis_complete']:
            return END
        return "analyze"
    
    # Build the graph
    workflow = StateGraph(TriageState)
    
    # Add nodes
    workflow.add_node("parse", parse_findings_node)
    workflow.add_node("analyze", analyze_finding_node)
    workflow.add_node("decide", make_decision_node)
    
    # Add edges
    workflow.add_edge("parse", "analyze")
    workflow.add_edge("analyze", "decide")
    workflow.add_conditional_edges(
        "decide",
        should_continue,
        {
            "analyze": "analyze",
            END: END
        }
    )
    
    # Set entry point
    workflow.set_entry_point("parse")
    
    return workflow.compile()


# Main execution
async def main():
    """Main entry point for the SAST triage agent"""
    
    # Initialize the agent
    agent = SASTTriageAgent(
        model_name="gemini-2.0-flash-exp",
        temperature=0.1
    )
    
    # Process findings
    results = await agent.process_all_findings(
        csv_path=DEFAULT_CSV_FILE,
        json_path=DEFAULT_JSON_FILE,
        output_path="triage_results.json"
    )
    
    return results


if __name__ == "__main__":
    # Run the agent
    asyncio.run(main())