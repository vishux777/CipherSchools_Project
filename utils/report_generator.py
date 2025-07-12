"""
Report Generator Module

Generates comprehensive analysis reports in multiple formats including
JSON, HTML, and text summaries for malware analysis results.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
import base64

class ReportGenerator:
    """
    Comprehensive report generator for malware analysis results
    """
    
    def __init__(self):
        """Initialize the report generator"""
        self.report_template = self._load_report_template()
        
    def _load_report_template(self):
        """Load HTML report template"""
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MalwareShield Pro - Analysis Report</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #0e1117;
                    color: #fafafa;
                    line-height: 1.6;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: #262730;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
                }
                .header {
                    text-align: center;
                    border-bottom: 2px solid #444;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }
                .threat-critical { background: linear-gradient(90deg, #8B0000, #DC143C); }
                .threat-high { background: linear-gradient(90deg, #FF4500, #FF6347); }
                .threat-medium { background: linear-gradient(90deg, #FF8C00, #FFA500); }
                .threat-low { background: linear-gradient(90deg, #228B22, #32CD32); }
                .threat-clean { background: linear-gradient(90deg, #228B22, #32CD32); }
                
                .threat-banner {
                    padding: 15px;
                    border-radius: 10px;
                    color: white;
                    font-weight: bold;
                    text-align: center;
                    margin: 20px 0;
                    font-size: 1.2em;
                }
                .section {
                    margin: 30px 0;
                    background-color: #1a1d29;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #00aaff;
                }
                .section h2 {
                    color: #00aaff;
                    margin-top: 0;
                }
                .grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }
                .metric {
                    background-color: #262730;
                    padding: 15px;
                    border-radius: 8px;
                    border: 1px solid #444;
                }
                .metric h3 {
                    margin: 0 0 10px 0;
                    color: #00aaff;
                }
                .code-block {
                    background-color: #1a1d29;
                    padding: 15px;
                    border-radius: 5px;
                    border: 1px solid #444;
                    font-family: 'Courier New', monospace;
                    white-space: pre-wrap;
                    overflow-x: auto;
                    margin: 10px 0;
                }
                .warning {
                    background-color: #2d1b1b;
                    border-left: 4px solid #ff4444;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                }
                .info {
                    background-color: #1b2d3a;
                    border-left: 4px solid #4444ff;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                }
                .success {
                    background-color: #1b2d1b;
                    border-left: 4px solid #44ff44;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                th, td {
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #444;
                }
                th {
                    background-color: #1a1d29;
                    color: #00aaff;
                }
                .footer {
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #444;
                    color: #888;
                }
            </style>
        </head>
        <body>
            <div class="container">
                {content}
            </div>
        </body>
        </html>
        """
    
    def generate_report(self, analysis_results: Dict[str, Any], format_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Generate a comprehensive analysis report
        
        Args:
            analysis_results (dict): Complete analysis results
            format_type (str): Type of report to generate
            
        Returns:
            dict: Generated report data
        """
        try:
            report_data = {
                'metadata': self._generate_metadata(analysis_results),
                'executive_summary': self._generate_executive_summary(analysis_results),
                'technical_details': self._generate_technical_details(analysis_results),
                'threat_assessment': self._generate_threat_assessment(analysis_results),
                'recommendations': self._generate_recommendations(analysis_results),
                'appendix': self._generate_appendix(analysis_results)
            }
            
            if format_type == "comprehensive":
                return report_data
            elif format_type == "summary":
                return {
                    'metadata': report_data['metadata'],
                    'executive_summary': report_data['executive_summary'],
                    'threat_assessment': report_data['threat_assessment']
                }
            else:
                return report_data
                
        except Exception as e:
            return {
                'error': f"Failed to generate report: {str(e)}",
                'status': 'error'
            }
    
    def _generate_metadata(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report metadata"""
        return {
            'report_id': f"MSP_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'analyzer_version': "MalwareShield Pro v1.0",
            'file_info': {
                'filename': results.get('filename', 'Unknown'),
                'file_size': results.get('file_size', 0),
                'file_size_human': self._format_file_size(results.get('file_size', 0)),
                'analysis_time': results.get('analysis_time', datetime.now().isoformat())
            },
            'analysis_engines': self._get_analysis_engines(results)
        }
    
    def _generate_executive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        threat_assessment = results.get('threat_assessment', {})
        threat_level = threat_assessment.get('level', 'UNKNOWN')
        threat_score = threat_assessment.get('score', 0)
        
        # Determine risk summary
        if threat_level in ['CRITICAL', 'HIGH']:
            risk_summary = "This file poses a significant security risk and should be quarantined immediately."
            action_required = "IMMEDIATE ACTION REQUIRED"
        elif threat_level == 'MEDIUM':
            risk_summary = "This file exhibits suspicious characteristics and should be investigated further."
            action_required = "INVESTIGATION RECOMMENDED"
        else:
            risk_summary = "This file appears to be clean with minimal security concerns."
            action_required = "NO IMMEDIATE ACTION REQUIRED"
        
        # Count detections
        virustotal_results = results.get('virustotal', {})
        vt_detections = 0
        if 'stats' in virustotal_results:
            vt_detections = virustotal_results['stats'].get('malicious', 0)
        
        return {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'risk_summary': risk_summary,
            'action_required': action_required,
            'key_findings': self._extract_key_findings(results),
            'detection_summary': {
                'virustotal_detections': vt_detections,
                'suspicious_patterns': len(results.get('patterns', {})),
                'threat_indicators': len(results.get('suspicious_indicators', []))
            }
        }
    
    def _generate_technical_details(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical analysis details"""
        return {
            'file_hashes': results.get('hashes', {}),
            'entropy_analysis': results.get('entropy', {}),
            'file_signature': results.get('file_signature', {}),
            'string_analysis': self._summarize_strings(results.get('strings', {})),
            'pattern_detection': results.get('patterns', {}),
            'suspicious_indicators': results.get('suspicious_indicators', []),
            'virustotal_analysis': self._summarize_virustotal(results.get('virustotal', {}))
        }
    
    def _generate_threat_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed threat assessment"""
        threat_data = results.get('threat_assessment', {})
        
        return {
            'overall_assessment': threat_data,
            'threat_vectors': self._identify_threat_vectors(results),
            'behavioral_indicators': self._extract_behavioral_indicators(results),
            'attribution_hints': self._extract_attribution_hints(results),
            'severity_breakdown': self._calculate_severity_breakdown(results)
        }
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate security recommendations"""
        recommendations = []
        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
        
        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                {
                    'priority': 'HIGH',
                    'action': 'Immediate Quarantine',
                    'description': 'Isolate this file immediately and prevent execution'
                },
                {
                    'priority': 'HIGH',
                    'action': 'Network Monitoring',
                    'description': 'Monitor network traffic for signs of compromise'
                },
                {
                    'priority': 'MEDIUM',
                    'action': 'System Scan',
                    'description': 'Perform full system scan to check for related threats'
                }
            ])
        
        if threat_level == 'MEDIUM':
            recommendations.extend([
                {
                    'priority': 'MEDIUM',
                    'action': 'Further Analysis',
                    'description': 'Submit to additional analysis engines for verification'
                },
                {
                    'priority': 'LOW',
                    'action': 'Sandboxing',
                    'description': 'Execute in isolated environment for behavioral analysis'
                }
            ])
        
        # Add pattern-specific recommendations
        patterns = results.get('patterns', {})
        if patterns.get('bitcoin_addresses'):
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Cryptocurrency Monitoring',
                'description': 'Monitor for unauthorized cryptocurrency transactions'
            })
        
        if patterns.get('api_injection_operations'):
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Process Monitoring',
                'description': 'Monitor for process injection and code modification attempts'
            })
        
        return recommendations
    
    def _generate_appendix(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate appendix with detailed technical data"""
        return {
            'raw_strings': self._format_strings_for_report(results.get('strings', {})),
            'pattern_matches': results.get('patterns', {}),
            'entropy_details': results.get('entropy', {}),
            'virustotal_raw': results.get('virustotal', {}),
            'analysis_metadata': {
                'total_analysis_time': 'N/A',  # Could be calculated if tracked
                'engines_used': self._get_analysis_engines(results),
                'confidence_level': results.get('threat_assessment', {}).get('confidence', 'unknown')
            }
        }
    
    def export_json(self, results: Dict[str, Any], pretty: bool = True) -> str:
        """
        Export results as JSON
        
        Args:
            results (dict): Analysis results
            pretty (bool): Whether to format JSON nicely
            
        Returns:
            str: JSON formatted results
        """
        try:
            if pretty:
                return json.dumps(results, indent=2, default=str, ensure_ascii=False)
            else:
                return json.dumps(results, default=str, ensure_ascii=False)
        except Exception as e:
            return json.dumps({'error': f'JSON export failed: {str(e)}'}, indent=2)
    
    def export_html(self, results: Dict[str, Any]) -> str:
        """
        Export results as HTML report
        
        Args:
            results (dict): Analysis results
            
        Returns:
            str: HTML formatted report
        """
        try:
            report_data = self.generate_report(results)
            html_content = self._build_html_content(report_data, results)
            return self.report_template.format(content=html_content)
        except Exception as e:
            return f"<html><body><h1>Report Generation Error</h1><p>{str(e)}</p></body></html>"
    
    def export_text_summary(self, results: Dict[str, Any]) -> str:
        """
        Export results as plain text summary
        
        Args:
            results (dict): Analysis results
            
        Returns:
            str: Text formatted summary
        """
        try:
            report_data = self.generate_report(results, "summary")
            
            summary = []
            summary.append("=" * 60)
            summary.append("MALWARESHIELD PRO - ANALYSIS REPORT")
            summary.append("=" * 60)
            summary.append("")
            
            # Metadata
            metadata = report_data['metadata']
            summary.append(f"Report ID: {metadata['report_id']}")
            summary.append(f"Generated: {metadata['generated_at']}")
            summary.append(f"File: {metadata['file_info']['filename']}")
            summary.append(f"Size: {metadata['file_info']['file_size_human']}")
            summary.append("")
            
            # Executive Summary
            exec_summary = report_data['executive_summary']
            summary.append("THREAT ASSESSMENT:")
            summary.append("-" * 20)
            summary.append(f"Threat Level: {exec_summary['threat_level']}")
            summary.append(f"Threat Score: {exec_summary['threat_score']}/100")
            summary.append(f"Risk Summary: {exec_summary['risk_summary']}")
            summary.append(f"Action Required: {exec_summary['action_required']}")
            summary.append("")
            
            # Key Findings
            if exec_summary['key_findings']:
                summary.append("KEY FINDINGS:")
                summary.append("-" * 15)
                for finding in exec_summary['key_findings']:
                    summary.append(f"• {finding}")
                summary.append("")
            
            # Detection Summary
            detection = exec_summary['detection_summary']
            summary.append("DETECTION SUMMARY:")
            summary.append("-" * 20)
            summary.append(f"VirusTotal Detections: {detection['virustotal_detections']}")
            summary.append(f"Suspicious Patterns: {detection['suspicious_patterns']}")
            summary.append(f"Threat Indicators: {detection['threat_indicators']}")
            summary.append("")
            
            summary.append("=" * 60)
            summary.append("End of Report")
            summary.append("=" * 60)
            
            return "\n".join(summary)
            
        except Exception as e:
            return f"Text export failed: {str(e)}"
    
    def _build_html_content(self, report_data: Dict[str, Any], raw_results: Dict[str, Any]) -> str:
        """Build HTML content for the report"""
        content = []
        
        # Header
        metadata = report_data['metadata']
        content.append(f"""
        <div class="header">
            <h1>🛡️ MalwareShield Pro</h1>
            <h2>Advanced Threat Analysis Report</h2>
            <p><strong>Report ID:</strong> {metadata['report_id']}</p>
            <p><strong>Generated:</strong> {metadata['generated_at']}</p>
        </div>
        """)
        
        # Threat Banner
        exec_summary = report_data['executive_summary']
        threat_level = exec_summary['threat_level'].lower()
        content.append(f"""
        <div class="threat-banner threat-{threat_level}">
            🚨 THREAT LEVEL: {exec_summary['threat_level']} - Score: {exec_summary['threat_score']}/100
        </div>
        """)
        
        # File Information
        file_info = metadata['file_info']
        content.append(f"""
        <div class="section">
            <h2>📄 File Information</h2>
            <div class="grid">
                <div class="metric">
                    <h3>File Name</h3>
                    <p>{file_info['filename']}</p>
                </div>
                <div class="metric">
                    <h3>File Size</h3>
                    <p>{file_info['file_size_human']} ({file_info['file_size']} bytes)</p>
                </div>
                <div class="metric">
                    <h3>Analysis Time</h3>
                    <p>{file_info['analysis_time']}</p>
                </div>
            </div>
        </div>
        """)
        
        # Executive Summary
        content.append(f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="{'warning' if threat_level in ['critical', 'high'] else 'info' if threat_level == 'medium' else 'success'}">
                <strong>Risk Summary:</strong> {exec_summary['risk_summary']}<br>
                <strong>Action Required:</strong> {exec_summary['action_required']}
            </div>
        </div>
        """)
        
        # Key Findings
        if exec_summary['key_findings']:
            findings_html = "<ul>"
            for finding in exec_summary['key_findings']:
                findings_html += f"<li>{finding}</li>"
            findings_html += "</ul>"
            
            content.append(f"""
            <div class="section">
                <h2>🔍 Key Findings</h2>
                {findings_html}
            </div>
            """)
        
        # Technical Details
        tech_details = report_data['technical_details']
        if tech_details.get('file_hashes'):
            hashes_html = ""
            for hash_type, hash_value in tech_details['file_hashes'].items():
                hashes_html += f"<div class='metric'><h3>{hash_type.upper()}</h3><p style='font-family: monospace; word-break: break-all;'>{hash_value}</p></div>"
            
            content.append(f"""
            <div class="section">
                <h2>🔐 File Hashes</h2>
                <div class="grid">
                    {hashes_html}
                </div>
            </div>
            """)
        
        # Recommendations
        recommendations = report_data['recommendations']
        if recommendations:
            rec_html = "<table><tr><th>Priority</th><th>Action</th><th>Description</th></tr>"
            for rec in recommendations:
                priority_color = '#ff4444' if rec['priority'] == 'HIGH' else '#ffaa44' if rec['priority'] == 'MEDIUM' else '#44ff44'
                rec_html += f"<tr><td style='color: {priority_color}; font-weight: bold;'>{rec['priority']}</td><td>{rec['action']}</td><td>{rec['description']}</td></tr>"
            rec_html += "</table>"
            
            content.append(f"""
            <div class="section">
                <h2>⚡ Recommendations</h2>
                {rec_html}
            </div>
            """)
        
        # Footer
        content.append(f"""
        <div class="footer">
            <p>Generated by MalwareShield Pro v1.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><small>This report is confidential and should be handled according to your organization's security policies.</small></p>
        </div>
        """)
        
        return "".join(content)
    
    # Helper methods
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        
        return f"{s} {size_names[i]}"
    
    def _get_analysis_engines(self, results: Dict[str, Any]) -> List[str]:
        """Get list of analysis engines used"""
        engines = ["Static Analysis Engine"]
        
        if 'virustotal' in results and 'error' not in results['virustotal']:
            engines.append("VirusTotal")
        
        if 'entropy' in results:
            engines.append("Entropy Analyzer")
        
        if 'patterns' in results:
            engines.append("Pattern Detection Engine")
        
        return engines
    
    def _extract_key_findings(self, results: Dict[str, Any]) -> List[str]:
        """Extract key findings from analysis results"""
        findings = []
        
        threat_assessment = results.get('threat_assessment', {})
        if threat_assessment.get('reasons'):
            findings.extend(threat_assessment['reasons'])
        
        # Add VirusTotal findings
        vt_results = results.get('virustotal', {})
        if 'stats' in vt_results:
            malicious = vt_results['stats'].get('malicious', 0)
            if malicious > 0:
                findings.append(f"VirusTotal detected malware with {malicious} engines")
        
        return findings[:10]  # Limit to top 10 findings
    
    def _summarize_strings(self, strings_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize string analysis results"""
        if not strings_data:
            return {}
        
        return {
            'total_ascii_strings': strings_data.get('total_ascii', 0),
            'total_unicode_strings': strings_data.get('total_unicode', 0),
            'sample_strings': strings_data.get('combined', [])[:20]  # First 20 strings
        }
    
    def _summarize_virustotal(self, vt_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize VirusTotal results"""
        if 'error' in vt_data:
            return {'status': 'error', 'message': vt_data['error']}
        
        stats = vt_data.get('stats', {})
        return {
            'detection_ratio': f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{stats.get('total', 0)}",
            'malicious_detections': stats.get('malicious', 0),
            'suspicious_detections': stats.get('suspicious', 0),
            'scan_date': vt_data.get('scan_date'),
            'top_detections': list(vt_data.get('scan_results', {}).keys())[:10]
        }
    
    def _identify_threat_vectors(self, results: Dict[str, Any]) -> List[str]:
        """Identify potential threat vectors"""
        vectors = []
        patterns = results.get('patterns', {})
        
        if patterns.get('api_network_operations'):
            vectors.append("Network Communication")
        
        if patterns.get('api_file_operations'):
            vectors.append("File System Modification")
        
        if patterns.get('api_registry_operations'):
            vectors.append("Registry Manipulation")
        
        if patterns.get('api_process_operations'):
            vectors.append("Process Manipulation")
        
        if patterns.get('bitcoin_addresses'):
            vectors.append("Cryptocurrency Operations")
        
        return vectors
    
    def _extract_behavioral_indicators(self, results: Dict[str, Any]) -> List[str]:
        """Extract behavioral indicators"""
        indicators = []
        
        suspicious_indicators = results.get('suspicious_indicators', [])
        for indicator in suspicious_indicators:
            indicators.append(f"{indicator.get('type', 'Unknown')}: {indicator.get('description', 'No description')}")
        
        return indicators
    
    def _extract_attribution_hints(self, results: Dict[str, Any]) -> List[str]:
        """Extract potential attribution hints"""
        hints = []
        
        # This could be expanded with more sophisticated attribution analysis
        patterns = results.get('patterns', {})
        
        if patterns.get('emails'):
            hints.append("Email addresses found - potential C&C communication")
        
        if patterns.get('urls'):
            hints.append("URLs found - potential data exfiltration endpoints")
        
        return hints
    
    def _calculate_severity_breakdown(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Calculate breakdown of severity levels"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        indicators = results.get('suspicious_indicators', [])
        for indicator in indicators:
            severity = indicator.get('severity', 'low')
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def _format_strings_for_report(self, strings_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format strings data for inclusion in report"""
        if not strings_data:
            return {}
        
        # Limit strings for report size
        formatted = {
            'ascii_strings': strings_data.get('ascii_strings', [])[:100],
            'unicode_strings': strings_data.get('unicode_strings', [])[:50],
            'total_count': strings_data.get('total_ascii', 0) + strings_data.get('total_unicode', 0)
        }
        
        return formatted

# Import math for file size formatting
import math
