#!/usr/bin/env python3
"""
Local LLM Powered Policy Gap Analysis and Improvement Module

This module identifies gaps in organizational policies by comparing them against
the CIS MS-ISAC NIST Cybersecurity Framework Policy Template Guide (2024).

Key Features:
- Uses lightweight local LLM (Llama 3.2 3B via Ollama)
- Fully offline operation
- No external API dependencies
- Generates comprehensive gap analysis reports
- Provides policy improvement roadmap

Author: Policy Analysis System
Date: February 2026
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import subprocess
import re
from datetime import datetime


class PolicyGapAnalyzer:
    """
    Analyzes organizational policies against NIST CSF framework standards.
    """
    
    def __init__(self, model_name: str = "llama3.2:3b"):
        """
        Initialize the Policy Gap Analyzer.
        
        Args:
            model_name: Name of the local Ollama model to use
        """
        self.model_name = model_name
        self.nist_framework = self._get_nist_framework_structure()
        
    def ensure_ollama_available(self) -> bool:
        """Check if Ollama is installed and accessible."""
        try:
            result = subprocess.run(
                ['which', 'ollama'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def ensure_model_available(self) -> bool:
        """Ensure the specified model is available locally."""
        try:
            result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if self.model_name in result.stdout:
                return True
            else:
                print(f"\n⚠️  Model '{self.model_name}' not found locally.")
                print(f"To install, run: ollama pull {self.model_name}")
                return False
        except Exception as e:
            print(f"Error checking model availability: {e}")
            return False
    
    def query_llm(self, prompt: str, temperature: float = 0.3) -> str:
        """
        Query the local LLM using Ollama.
        
        Args:
            prompt: The prompt to send to the LLM
            temperature: Sampling temperature (0.0-1.0)
            
        Returns:
            The LLM's response as a string
        """
        try:
            # Run ollama with the prompt
            result = subprocess.run(
                ['ollama', 'run', self.model_name],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode != 0:
                raise Exception(f"Ollama error: {result.stderr}")
                
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Error: LLM query timed out after 180 seconds"
        except Exception as e:
            return f"Error querying LLM: {str(e)}"
    
    def extract_policy_content(self, policy_file: Path) -> str:
        """
        Extract text content from policy document.
        
        Args:
            policy_file: Path to the policy document
            
        Returns:
            Extracted text content
        """
        if not policy_file.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_file}")
        
        # Support .txt and .md files
        if policy_file.suffix in ['.txt', '.md']:
            with open(policy_file, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            raise ValueError(f"Unsupported file format: {policy_file.suffix}. Use .txt or .md")
    
    def _get_nist_framework_structure(self) -> Dict:
        """
        Returns the NIST Cybersecurity Framework core structure.
        Based on CIS MS-ISAC NIST CSF Policy Template Guide (2024).
        """
        return {
            "IDENTIFY": {
                "description": "Develop organizational understanding to manage cybersecurity risk",
                "categories": {
                    "Asset Management (ID.AM)": [
                        "Physical devices and systems inventory",
                        "Software platforms and applications inventory",
                        "Organizational communication and data flows mapping",
                        "External information systems cataloging",
                        "Resources prioritization based on classification and criticality"
                    ],
                    "Business Environment (ID.BE)": [
                        "Organization's role in the supply chain identification",
                        "Organization's place in critical infrastructure identification",
                        "Priorities for organizational mission and objectives",
                        "Dependencies and critical functions identification",
                        "Resilience requirements establishment"
                    ],
                    "Governance (ID.GV)": [
                        "Organizational cybersecurity policy establishment",
                        "Cybersecurity roles and responsibilities coordination",
                        "Legal and regulatory requirements understanding",
                        "Governance and risk management processes alignment",
                        "Cybersecurity incorporated into organizational risk management"
                    ],
                    "Risk Assessment (ID.RA)": [
                        "Asset vulnerabilities identification and documentation",
                        "Cyber threat intelligence collection and analysis",
                        "Internal and external threats identification",
                        "Potential business impacts and likelihoods determination",
                        "Threats, vulnerabilities, likelihoods, and impacts for risk determination"
                    ],
                    "Risk Management Strategy (ID.RM)": [
                        "Risk management processes establishment and management",
                        "Organizational risk tolerance determination and communication",
                        "Organization's risk determination and review"
                    ],
                    "Supply Chain Risk Management (ID.SC)": [
                        "Cyber supply chain risk management processes identification",
                        "Suppliers and third-party partners identified and prioritized",
                        "Contracts with suppliers and partners for cybersecurity requirements",
                        "Suppliers and third-party partners routinely assessed",
                        "Response and recovery planning with suppliers and partners"
                    ]
                }
            },
            "PROTECT": {
                "description": "Develop and implement appropriate safeguards",
                "categories": {
                    "Identity Management and Access Control (PR.AC)": [
                        "Identities and credentials issued, managed, verified, revoked, and audited",
                        "Physical access to assets managed",
                        "Remote access managed",
                        "Access permissions and authorizations managed",
                        "Network integrity protected through segregation",
                        "Identities proofed and bound to credentials and asserted in interactions"
                    ],
                    "Awareness and Training (PR.AT)": [
                        "All users informed and trained on cybersecurity",
                        "Privileged users understand roles and responsibilities",
                        "Third-party stakeholders understand roles and responsibilities",
                        "Senior executives understand roles and responsibilities",
                        "Physical and cybersecurity personnel understand roles"
                    ],
                    "Data Security (PR.DS)": [
                        "Data-at-rest protected",
                        "Data-in-transit protected",
                        "Assets formally managed through development lifecycle",
                        "Adequate capacity maintained for availability",
                        "Protections against data leaks implemented",
                        "Integrity checking mechanisms for verification",
                        "Development and testing environment separation"
                    ],
                    "Information Protection Processes (PR.IP)": [
                        "Baseline configuration created and maintained",
                        "System development life cycle for managing systems",
                        "Configuration change control processes",
                        "Backups of information conducted and maintained",
                        "Physical operating environment for assets managed",
                        "Data destruction conducted according to policy",
                        "Protection processes improved based on lessons learned",
                        "Effectiveness of protection technologies shared",
                        "Response plans and recovery plans in place and managed",
                        "Response and recovery plans tested",
                        "Cybersecurity included in HR practices",
                        "Vulnerability management plan developed and implemented"
                    ],
                    "Maintenance (PR.MA)": [
                        "Maintenance and repair of assets performed and logged",
                        "Remote maintenance approved, logged, and performed securely"
                    ],
                    "Protective Technology (PR.PT)": [
                        "Audit/log records determined, documented, implemented, and reviewed",
                        "Removable media protected and usage restricted",
                        "Least functionality principle incorporated",
                        "Communications and control networks protected",
                        "Mechanisms to achieve resilience requirements implemented"
                    ]
                }
            },
            "DETECT": {
                "description": "Develop and implement activities to identify cybersecurity events",
                "categories": {
                    "Anomalies and Events (DE.AE)": [
                        "Baseline of network operations and flows established",
                        "Detected events analyzed to understand attack targets and methods",
                        "Event data aggregated and correlated from multiple sources",
                        "Impact of events determined",
                        "Incident alert thresholds established"
                    ],
                    "Security Continuous Monitoring (DE.CM)": [
                        "Network monitored to detect potential cybersecurity events",
                        "Physical environment monitored for cybersecurity events",
                        "Personnel activity monitored for cybersecurity events",
                        "Malicious code detected",
                        "Unauthorized mobile code detected",
                        "External service provider activity monitored",
                        "Monitoring for unauthorized personnel, connections, and devices",
                        "Vulnerability scans performed"
                    ],
                    "Detection Processes (DE.DP)": [
                        "Roles and responsibilities for detection defined",
                        "Detection activities comply with requirements",
                        "Detection processes tested",
                        "Event detection information communicated",
                        "Detection processes continuously improved"
                    ]
                }
            },
            "RESPOND": {
                "description": "Develop and implement appropriate activities for detected cybersecurity incidents",
                "categories": {
                    "Response Planning (RS.RP)": [
                        "Response plan executed during or after incident"
                    ],
                    "Communications (RS.CO)": [
                        "Personnel know their roles and order of operations",
                        "Incidents reported consistent with established criteria",
                        "Information shared with designated external stakeholders",
                        "Coordination with stakeholders occurs",
                        "Voluntary information sharing occurs with external stakeholders"
                    ],
                    "Analysis (RS.AN)": [
                        "Notifications from detection systems investigated",
                        "Impact of incident understood",
                        "Forensics performed",
                        "Incidents categorized consistent with response plans",
                        "Processes established to receive and analyze vulnerability disclosures"
                    ],
                    "Mitigation (RS.MI)": [
                        "Incidents contained",
                        "Incidents mitigated",
                        "Newly identified vulnerabilities mitigated or documented"
                    ],
                    "Improvements (RS.IM)": [
                        "Response plans incorporate lessons learned",
                        "Response strategies updated"
                    ]
                }
            },
            "RECOVER": {
                "description": "Develop and implement activities to maintain resilience and restore capabilities",
                "categories": {
                    "Recovery Planning (RC.RP)": [
                        "Recovery plan executed during or after cybersecurity incident"
                    ],
                    "Improvements (RC.IM)": [
                        "Recovery plans incorporate lessons learned",
                        "Recovery strategies updated"
                    ],
                    "Communications (RC.CO)": [
                        "Public relations managed",
                        "Reputation repaired after incident",
                        "Recovery activities communicated to stakeholders"
                    ]
                }
            }
        }
    
    def analyze_policy_gaps(self, policy_content: str, policy_type: str) -> Dict:
        """
        Analyze policy against NIST CSF framework to identify gaps.
        
        Args:
            policy_content: The policy document content
            policy_type: Type of policy (ISMS, Data Privacy, Patch Management, Risk Management)
            
        Returns:
            Dictionary containing gap analysis results
        """
        print(f"\n🔍 Analyzing {policy_type} policy for gaps...")
        
        # Determine relevant NIST functions based on policy type
        relevant_functions = self._get_relevant_nist_functions(policy_type)
        
        gaps = {
            "policy_type": policy_type,
            "analysis_date": datetime.now().isoformat(),
            "nist_functions_analyzed": list(relevant_functions.keys()),
            "identified_gaps": [],
            "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        
        # Analyze each relevant NIST function
        for function_name, function_data in relevant_functions.items():
            print(f"  → Analyzing {function_name} function...")
            
            for category, requirements in function_data["categories"].items():
                category_gaps = self._analyze_category(
                    policy_content, 
                    function_name, 
                    category, 
                    requirements
                )
                gaps["identified_gaps"].extend(category_gaps)
        
        # Calculate severity summary
        for gap in gaps["identified_gaps"]:
            severity = gap.get("severity", "medium")
            gaps["severity_summary"][severity] += 1
        
        return gaps
    
    def _get_relevant_nist_functions(self, policy_type: str) -> Dict:
        """Get NIST functions relevant to the policy type."""
        policy_type_lower = policy_type.lower()
        
        # All policies should cover all functions, but with different emphasis
        if "isms" in policy_type_lower or "information security" in policy_type_lower:
            return self.nist_framework  # All functions
        elif "data privacy" in policy_type_lower or "data security" in policy_type_lower:
            return {
                "IDENTIFY": self.nist_framework["IDENTIFY"],
                "PROTECT": self.nist_framework["PROTECT"],
                "DETECT": self.nist_framework["DETECT"]
            }
        elif "patch" in policy_type_lower:
            return {
                "IDENTIFY": self.nist_framework["IDENTIFY"],
                "PROTECT": self.nist_framework["PROTECT"],
                "DETECT": self.nist_framework["DETECT"]
            }
        elif "risk" in policy_type_lower:
            return {
                "IDENTIFY": self.nist_framework["IDENTIFY"],
                "RESPOND": self.nist_framework["RESPOND"],
                "RECOVER": self.nist_framework["RECOVER"]
            }
        else:
            return self.nist_framework  # Default to all
    
    def _analyze_category(self, policy_content: str, function_name: str, 
                          category: str, requirements: List[str]) -> List[Dict]:
        """
        Analyze a specific NIST category against the policy.
        
        Returns:
            List of identified gaps
        """
        gaps = []
        
        for requirement in requirements:
            # Check if requirement is addressed in policy
            is_addressed = self._check_requirement_coverage(policy_content, requirement)
            
            if not is_addressed:
                gap = {
                    "nist_function": function_name,
                    "nist_category": category,
                    "requirement": requirement,
                    "severity": self._assess_gap_severity(function_name, category, requirement),
                    "current_coverage": "Not addressed",
                    "recommendation": self._generate_recommendation(requirement)
                }
                gaps.append(gap)
        
        return gaps
    
    def _check_requirement_coverage(self, policy_content: str, requirement: str) -> bool:
        """
        Check if a requirement is covered in the policy using keyword analysis.
        
        Args:
            policy_content: The policy text
            requirement: The NIST requirement to check
            
        Returns:
            True if requirement appears to be covered
        """
        # Extract key concepts from requirement
        keywords = self._extract_keywords(requirement)
        
        # Convert to lowercase for comparison
        policy_lower = policy_content.lower()
        
        # Check if majority of keywords are present
        matches = sum(1 for kw in keywords if kw in policy_lower)
        coverage_ratio = matches / len(keywords) if keywords else 0
        
        return coverage_ratio >= 0.6  # 60% keyword match threshold
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract meaningful keywords from text."""
        # Remove common words and extract key terms
        common_words = {'the', 'and', 'for', 'are', 'with', 'from', 'their', 'this', 'that'}
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = [w for w in words if w not in common_words and len(w) > 3]
        return keywords
    
    def _assess_gap_severity(self, function: str, category: str, requirement: str) -> str:
        """Assess the severity of a policy gap."""
        # Critical: Governance, Access Control, Data Protection
        critical_keywords = ['password', 'encryption', 'access control', 'authentication', 
                            'governance', 'data protection', 'backup']
        
        # High: Risk Management, Incident Response
        high_keywords = ['risk', 'incident', 'vulnerability', 'threat', 'monitoring']
        
        # Medium: Training, Documentation
        medium_keywords = ['training', 'awareness', 'documentation', 'testing']
        
        requirement_lower = requirement.lower()
        
        if any(kw in requirement_lower for kw in critical_keywords):
            return "critical"
        elif any(kw in requirement_lower for kw in high_keywords):
            return "high"
        elif any(kw in requirement_lower for kw in medium_keywords):
            return "medium"
        else:
            return "low"
    
    def _generate_recommendation(self, requirement: str) -> str:
        """Generate a recommendation to address the gap."""
        return f"Implement controls and procedures to address: {requirement}"
    
    def generate_revised_policy(self, policy_content: str, gaps: Dict, 
                               use_llm: bool = True) -> str:
        """
        Generate a revised policy that addresses identified gaps.
        
        Args:
            policy_content: Original policy content
            gaps: Gap analysis results
            use_llm: Whether to use LLM for generation (if False, uses template-based approach)
            
        Returns:
            Revised policy text
        """
        print(f"\n📝 Generating revised policy...")
        
        if use_llm and self.ensure_ollama_available():
            return self._generate_policy_with_llm(policy_content, gaps)
        else:
            return self._generate_policy_template_based(policy_content, gaps)
    
    def _generate_policy_with_llm(self, policy_content: str, gaps: Dict) -> str:
        """Generate revised policy using local LLM."""
        print("  → Using local LLM for policy revision...")
        
        # Prepare gaps summary
        gaps_summary = self._format_gaps_for_llm(gaps)
        
        prompt = f"""You are a cybersecurity policy expert. Your task is to revise an organizational policy to address identified gaps based on the NIST Cybersecurity Framework.

ORIGINAL POLICY:
{policy_content[:2000]}... [truncated]

IDENTIFIED GAPS:
{gaps_summary}

TASK:
Generate ONLY the missing sections that need to be added to the policy to address the critical and high-severity gaps. Format each section with:
1. Section title
2. Clear policy statements
3. Specific requirements

Focus on the top 5 most critical gaps. Be concise and specific.

REVISED POLICY SECTIONS:"""

        response = self.query_llm(prompt)
        
        return f"{policy_content}\n\n## RECOMMENDED ADDITIONS\n\n{response}"
    
    def _format_gaps_for_llm(self, gaps: Dict) -> str:
        """Format gaps for LLM consumption."""
        output = []
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_gaps = sorted(
            gaps["identified_gaps"], 
            key=lambda x: severity_order.get(x["severity"], 3)
        )
        
        for i, gap in enumerate(sorted_gaps[:10], 1):  # Top 10 gaps
            output.append(
                f"{i}. [{gap['severity'].upper()}] {gap['nist_category']}: "
                f"{gap['requirement']}"
            )
        
        return "\n".join(output)
    
    def _generate_policy_template_based(self, policy_content: str, gaps: Dict) -> str:
        """Generate revised policy using template-based approach (fallback)."""
        print("  → Using template-based policy revision...")
        
        additions = ["\n\n## RECOMMENDED POLICY ADDITIONS\n"]
        additions.append("*Generated based on NIST Cybersecurity Framework gap analysis*\n")
        
        # Group gaps by function
        by_function = {}
        for gap in gaps["identified_gaps"]:
            func = gap["nist_function"]
            if func not in by_function:
                by_function[func] = []
            by_function[func].append(gap)
        
        # Generate sections for each function
        for function, function_gaps in by_function.items():
            additions.append(f"\n### {function}\n")
            
            # Group by severity
            critical_gaps = [g for g in function_gaps if g["severity"] == "critical"]
            high_gaps = [g for g in function_gaps if g["severity"] == "high"]
            
            if critical_gaps:
                additions.append("\n#### Critical Requirements\n")
                for gap in critical_gaps[:5]:  # Top 5 critical
                    additions.append(f"- {gap['requirement']}\n")
                    additions.append(f"  *Recommendation: {gap['recommendation']}*\n")
            
            if high_gaps:
                additions.append("\n#### High Priority Requirements\n")
                for gap in high_gaps[:5]:  # Top 5 high
                    additions.append(f"- {gap['requirement']}\n")
        
        return policy_content + "\n".join(additions)
    
    def generate_improvement_roadmap(self, gaps: Dict) -> Dict:
        """
        Generate a roadmap for policy improvement aligned with NIST CSF.
        
        Args:
            gaps: Gap analysis results
            
        Returns:
            Improvement roadmap dictionary
        """
        print(f"\n🗺️  Generating improvement roadmap...")
        
        roadmap = {
            "overview": {
                "total_gaps": len(gaps["identified_gaps"]),
                "critical": gaps["severity_summary"]["critical"],
                "high": gaps["severity_summary"]["high"],
                "medium": gaps["severity_summary"]["medium"],
                "low": gaps["severity_summary"]["low"]
            },
            "phases": []
        }
        
        # Phase 1: Critical gaps (0-3 months)
        critical_gaps = [g for g in gaps["identified_gaps"] if g["severity"] == "critical"]
        if critical_gaps:
            roadmap["phases"].append({
                "phase": 1,
                "timeline": "0-3 months",
                "priority": "Critical",
                "focus": "Address critical security gaps",
                "actions": [
                    {"gap": g["requirement"], "nist_category": g["nist_category"]}
                    for g in critical_gaps[:10]
                ]
            })
        
        # Phase 2: High priority gaps (3-6 months)
        high_gaps = [g for g in gaps["identified_gaps"] if g["severity"] == "high"]
        if high_gaps:
            roadmap["phases"].append({
                "phase": 2,
                "timeline": "3-6 months",
                "priority": "High",
                "focus": "Strengthen security controls",
                "actions": [
                    {"gap": g["requirement"], "nist_category": g["nist_category"]}
                    for g in high_gaps[:10]
                ]
            })
        
        # Phase 3: Medium priority gaps (6-12 months)
        medium_gaps = [g for g in gaps["identified_gaps"] if g["severity"] == "medium"]
        if medium_gaps:
            roadmap["phases"].append({
                "phase": 3,
                "timeline": "6-12 months",
                "priority": "Medium",
                "focus": "Enhance organizational maturity",
                "actions": [
                    {"gap": g["requirement"], "nist_category": g["nist_category"]}
                    for g in medium_gaps[:10]
                ]
            })
        
        # Phase 4: Low priority gaps (12+ months)
        low_gaps = [g for g in gaps["identified_gaps"] if g["severity"] == "low"]
        if low_gaps:
            roadmap["phases"].append({
                "phase": 4,
                "timeline": "12+ months",
                "priority": "Low",
                "focus": "Achieve comprehensive coverage",
                "actions": [
                    {"gap": g["requirement"], "nist_category": g["nist_category"]}
                    for g in low_gaps[:10]
                ]
            })
        
        return roadmap
    
    def save_results(self, output_dir: Path, policy_type: str, 
                    gaps: Dict, revised_policy: str, roadmap: Dict):
        """
        Save all analysis results to files.
        
        Args:
            output_dir: Directory to save results
            policy_type: Type of policy analyzed
            gaps: Gap analysis results
            revised_policy: Revised policy content
            roadmap: Improvement roadmap
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save gap analysis
        gap_file = output_dir / f"{policy_type}_gap_analysis.json"
        with open(gap_file, 'w') as f:
            json.dump(gaps, f, indent=2)
        print(f"✅ Gap analysis saved: {gap_file}")
        
        # Save revised policy
        policy_file = output_dir / f"{policy_type}_revised_policy.md"
        with open(policy_file, 'w') as f:
            f.write(revised_policy)
        print(f"✅ Revised policy saved: {policy_file}")
        
        # Save roadmap
        roadmap_file = output_dir / f"{policy_type}_improvement_roadmap.json"
        with open(roadmap_file, 'w') as f:
            json.dump(roadmap, f, indent=2)
        print(f"✅ Improvement roadmap saved: {roadmap_file}")
        
        # Generate summary report
        self._generate_summary_report(output_dir, policy_type, gaps, roadmap)
    
    def _generate_summary_report(self, output_dir: Path, policy_type: str, 
                                 gaps: Dict, roadmap: Dict):
        """Generate a human-readable summary report."""
        report_file = output_dir / f"{policy_type}_summary_report.md"
        
        report = [
            f"# Policy Gap Analysis Report",
            f"\n**Policy Type:** {policy_type}",
            f"\n**Analysis Date:** {gaps['analysis_date']}",
            f"\n**Analysis Framework:** NIST Cybersecurity Framework (CIS MS-ISAC 2024)",
            f"\n\n## Executive Summary\n",
            f"Total Gaps Identified: **{len(gaps['identified_gaps'])}**\n",
            f"- Critical: {gaps['severity_summary']['critical']}",
            f"- High: {gaps['severity_summary']['high']}",
            f"- Medium: {gaps['severity_summary']['medium']}",
            f"- Low: {gaps['severity_summary']['low']}\n",
            f"\n## NIST Functions Analyzed\n"
        ]
        
        for func in gaps['nist_functions_analyzed']:
            report.append(f"- {func}")
        
        report.append("\n## Top 10 Critical Gaps\n")
        
        critical_and_high = [
            g for g in gaps['identified_gaps'] 
            if g['severity'] in ['critical', 'high']
        ][:10]
        
        for i, gap in enumerate(critical_and_high, 1):
            report.append(
                f"\n### {i}. [{gap['severity'].upper()}] {gap['nist_category']}\n"
                f"**Requirement:** {gap['requirement']}\n"
                f"**Recommendation:** {gap['recommendation']}\n"
            )
        
        report.append("\n## Improvement Roadmap\n")
        
        for phase in roadmap['phases']:
            report.append(
                f"\n### Phase {phase['phase']}: {phase['priority']} Priority "
                f"({phase['timeline']})\n"
                f"**Focus:** {phase['focus']}\n"
                f"**Key Actions:** {len(phase['actions'])} items\n"
            )
        
        with open(report_file, 'w') as f:
            f.write("\n".join(report))
        
        print(f"✅ Summary report saved: {report_file}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Local LLM Powered Policy Gap Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single policy
  python policy_gap_analyzer.py --policy policies/isms_policy.txt --type ISMS
  
  # Analyze with LLM-powered revision
  python policy_gap_analyzer.py --policy policies/data_privacy.txt --type "Data Privacy" --use-llm
  
  # Analyze multiple policies
  python policy_gap_analyzer.py --policy-dir policies/ --output results/
        """
    )
    
    parser.add_argument(
        '--policy', 
        type=Path,
        help='Path to policy document (.txt or .md)'
    )
    parser.add_argument(
        '--policy-dir',
        type=Path,
        help='Directory containing multiple policies'
    )
    parser.add_argument(
        '--type',
        default='General Security',
        help='Policy type (ISMS, Data Privacy, Patch Management, Risk Management)'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('output'),
        help='Output directory for results (default: output/)'
    )
    parser.add_argument(
        '--use-llm',
        action='store_true',
        help='Use local LLM for policy revision (requires Ollama)'
    )
    parser.add_argument(
        '--model',
        default='llama3.2:3b',
        help='Ollama model to use (default: llama3.2:3b)'
    )
    
    args = parser.parse_args()
    
    if not args.policy and not args.policy_dir:
        parser.error("Either --policy or --policy-dir must be specified")
    
    # Initialize analyzer
    print("=" * 70)
    print("🔐 LOCAL LLM POWERED POLICY GAP ANALYSIS TOOL")
    print("=" * 70)
    print(f"Framework: NIST Cybersecurity Framework (CIS MS-ISAC 2024)")
    print(f"Model: {args.model}")
    print(f"LLM-Enhanced Revision: {'Enabled' if args.use_llm else 'Disabled'}")
    print("=" * 70)
    
    analyzer = PolicyGapAnalyzer(model_name=args.model)
    
    # Check if LLM is available
    if args.use_llm:
        if not analyzer.ensure_ollama_available():
            print("\n⚠️  WARNING: Ollama not found. Install from https://ollama.ai")
            print("Falling back to template-based policy revision.\n")
            args.use_llm = False
        elif not analyzer.ensure_model_available():
            print(f"\n⚠️  WARNING: Model {args.model} not available.")
            print("Falling back to template-based policy revision.\n")
            args.use_llm = False
    
    # Process policies
    policies_to_analyze = []
    
    if args.policy:
        policies_to_analyze.append((args.policy, args.type))
    elif args.policy_dir:
        for policy_file in args.policy_dir.glob('*.txt'):
            # Infer type from filename
            policy_type = policy_file.stem.replace('_', ' ').title()
            policies_to_analyze.append((policy_file, policy_type))
        for policy_file in args.policy_dir.glob('*.md'):
            policy_type = policy_file.stem.replace('_', ' ').title()
            policies_to_analyze.append((policy_file, policy_type))
    
    if not policies_to_analyze:
        print("\n❌ No policies found to analyze.")
        sys.exit(1)
    
    # Analyze each policy
    for policy_path, policy_type in policies_to_analyze:
        print(f"\n{'='*70}")
        print(f"📄 Analyzing: {policy_path.name}")
        print(f"📋 Type: {policy_type}")
        print(f"{'='*70}")
        
        try:
            # Extract policy content
            policy_content = analyzer.extract_policy_content(policy_path)
            
            # Analyze gaps
            gaps = analyzer.analyze_policy_gaps(policy_content, policy_type)
            
            # Generate revised policy
            revised_policy = analyzer.generate_revised_policy(
                policy_content, 
                gaps, 
                use_llm=args.use_llm
            )
            
            # Generate improvement roadmap
            roadmap = analyzer.generate_improvement_roadmap(gaps)
            
            # Save results
            analyzer.save_results(
                args.output, 
                policy_type.lower().replace(' ', '_'),
                gaps,
                revised_policy,
                roadmap
            )
            
            print(f"\n✅ Analysis complete for {policy_type}")
            
        except Exception as e:
            print(f"\n❌ Error analyzing {policy_path}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*70}")
    print(f"✅ ALL ANALYSES COMPLETE")
    print(f"📁 Results saved to: {args.output.absolute()}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
