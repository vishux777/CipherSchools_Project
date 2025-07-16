"""
Report Generator for MalwareShield Pro - FINAL WORKING VERSION
Generates PDF and JSON reports from analysis results using HTML-to-PDF conversion
Built with 🛡️ by [Vishwas]
"""

import json
import io
from datetime import datetime
from typing import Dict, Any, Optional
import os

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

class ReportGenerator:
    """Professional report generator for malware analysis using HTML-to-PDF conversion"""
    
    def __init__(self):
        self.colors = {
            'CLEAN': '#28a745',
            'LOW': '#ffc107', 
            'MEDIUM': '#fd7e14',
            'HIGH': '#dc3545',
            'CRITICAL': '#721c24'
        }
        
        # Setup Jinja2 environment
        self.jinja_env = None
        if JINJA2_AVAILABLE:
            template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
            if os.path.exists(template_dir):
                self.jinja_env = Environment(loader=FileSystemLoader(template_dir))
            else:
                self.jinja_env = None
    
    def _get_threat_color(self, threat_level: str) -> str:
        """Get color for threat level"""
        return self.colors.get(threat_level, '#6c757d')
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """
        Generate PDF report from analysis results using HTML-to-PDF conversion
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            PDF report as bytes
        """
        try:
            # Clean and validate the analysis results
            cleaned_results = self._clean_analysis_results(analysis_results)
            
            if WEASYPRINT_AVAILABLE:
                return self._generate_html_to_pdf_report(cleaned_results)
            else:
                return self._generate_simple_text_report(cleaned_results)
                
        except Exception as e:
            return self._generate_error_report(str(e))
    
    def _clean_analysis_results(self, results: Any) -> Dict[str, Any]:
        """Clean and validate analysis results to ensure proper format"""
        if not isinstance(results, dict):
            # Handle the case where results is not a dict
            if hasattr(results, '__dict__'):
                results = results.__dict__
            else:
                results = {'error': f'Invalid data format: {type(results)}', 'raw_data': str(results)}
        
        # Ensure required fields exist with defaults
        cleaned = {
            'filename': results.get('filename', 'Unknown'),
            'file_size': int(results.get('file_size', 0)),
            'file_type': results.get('file_type', 'Unknown'),
            'analysis_time': results.get('analysis_time', datetime.now().isoformat()),
            'hashes': results.get('hashes', {}),
            'threat_assessment': results.get('threat_assessment', {}),
            'entropy': float(results.get('entropy', 0.0)),
            'strings': results.get('strings', []),
            'suspicious_indicators': results.get('suspicious_indicators', []),
            'virustotal': results.get('virustotal', {}),
        }
        
        # Ensure threat_assessment has required fields
        if not cleaned['threat_assessment']:
            cleaned['threat_assessment'] = {
                'level': 'UNKNOWN',
                'score': 0,
                'confidence': 0.0,
                'reasoning': []
            }
        
        return cleaned
    
    def _generate_html_to_pdf_report(self, results: Dict[str, Any]) -> bytes:
        """Generate PDF report using weasyprint HTML-to-PDF conversion"""
        try:
            # Generate simple, clean HTML content
            html_content = self._generate_simple_html_content(results)
            
            # Convert HTML to PDF with minimal settings
            html_doc = HTML(string=html_content, base_url='.')
            
            # Generate PDF with basic settings
            pdf_bytes = html_doc.write_pdf()
            
            # Validate PDF output
            if pdf_bytes and len(pdf_bytes) > 100 and pdf_bytes[:4] == b'%PDF':
                return pdf_bytes
            else:
                return self._generate_simple_text_report(results)
                
        except Exception as e:
            return self._generate_simple_text_report(results)
    
    def _generate_simple_html_content(self, results: Dict[str, Any]) -> str:
        """Generate simple HTML content for PDF conversion"""
        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
        threat_color = self._get_threat_color(threat_level)
        
        def safe_str(value):
            """Convert value to safe string for HTML"""
            if value is None:
                return 'Unknown'
            return str(value).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MalwareShield Pro Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .section {{ margin-bottom: 20px; }}
        .section h3 {{ color: #0066cc; border-bottom: 2px solid #0066cc; padding-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
        td {{ padding: 8px; border-bottom: 1px solid #eee; }}
        td:first-child {{ width: 30%; font-weight: bold; }}
        .threat-level {{ padding: 10px; border-radius: 5px; margin: 10px 0; color: white; background-color: {threat_color}; }}
        ul {{ margin: 10px 0; }}
        .hash {{ font-family: monospace; font-size: 11px; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ MalwareShield Pro</h1>
        <h2>Malware Analysis Report</h2>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h3>File Information</h3>
        <table>
            <tr><td>Filename:</td><td>{safe_str(results.get('filename'))}</td></tr>
            <tr><td>File Size:</td><td>{results.get('file_size', 0):,} bytes</td></tr>
            <tr><td>File Type:</td><td>{safe_str(results.get('file_type'))}</td></tr>
            <tr><td>Analysis Time:</td><td>{safe_str(results.get('analysis_time', ''))[:19]}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h3>Hash Analysis</h3>
        <table>"""
        
        hashes = results.get('hashes', {})
        if hashes:
            html += f"""
            <tr><td>MD5:</td><td class="hash">{safe_str(hashes.get('md5', 'Not calculated'))}</td></tr>
            <tr><td>SHA1:</td><td class="hash">{safe_str(hashes.get('sha1', 'Not calculated'))}</td></tr>
            <tr><td>SHA256:</td><td class="hash">{safe_str(hashes.get('sha256', 'Not calculated'))}</td></tr>"""
        else:
            html += '<tr><td colspan="2">Hash calculation not available</td></tr>'
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h3>Threat Assessment</h3>"""
        
        threat_data = results.get('threat_assessment', {})
        if threat_data:
            level = threat_data.get('level', 'UNKNOWN')
            score = threat_data.get('score', 0)
            confidence = threat_data.get('confidence', 0)
            
            html += f"""
        <div class="threat-level">
            <strong>Threat Level: {level} ({score}/100)</strong><br>
            <strong>Confidence: {confidence:.1f}%</strong>
        </div>"""
            
            reasoning = threat_data.get('reasoning', [])
            if reasoning:
                html += '<h4>Assessment Reasoning:</h4><ul>'
                for reason in reasoning[:5]:
                    html += f'<li>{safe_str(reason)}</li>'
                html += '</ul>'
        
        html += """
    </div>
    
    <div class="section">
        <h3>Technical Details</h3>
        <table>"""
        
        html += f"""
            <tr><td>Entropy:</td><td>{results.get('entropy', 0):.3f}</td></tr>
            <tr><td>Extracted Strings:</td><td>{len(results.get('strings', []))}</td></tr>
            <tr><td>Suspicious Indicators:</td><td>{len(results.get('suspicious_indicators', []))}</td></tr>
        </table>
    </div>"""
        
        # Suspicious Indicators
        indicators = results.get('suspicious_indicators', [])
        if indicators:
            html += """
    <div class="section">
        <h3>Suspicious Indicators</h3>
        <ul>"""
            for indicator in indicators[:10]:
                html += f'<li>{safe_str(indicator)}</li>'
            html += '</ul></div>'
        
        # VirusTotal Results
        vt_results = results.get('virustotal', {})
        if vt_results and vt_results.get('available'):
            detections = vt_results.get('detections', 0)
            total_engines = vt_results.get('total_engines', 0)
            
            html += f"""
    <div class="section">
        <h3>VirusTotal Results</h3>
        <p><strong>Detection Rate:</strong> {detections}/{total_engines} engines</p>"""
            
            if detections > 0:
                detected_engines = vt_results.get('detected_engines', [])
                html += '<h4>Detected by:</h4><ul>'
                for engine in detected_engines[:5]:
                    html += f'<li>{safe_str(engine)}</li>'
                html += '</ul>'
            html += '</div>'
        
        # Recommendations
        recommendations = self._get_recommendations(threat_level, results)
        html += """
    <div class="section">
        <h3>Recommendations</h3>
        <ul>"""
        for rec in recommendations[:8]:  # Limit recommendations
            html += f'<li>{safe_str(rec)}</li>'
        
        html += """
        </ul>
    </div>
    
    <div style="text-align: center; margin-top: 30px; color: #666; font-style: italic;">
        <p>Built with MalwareShield Pro by [Vishwas]</p>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_simple_text_report(self, results: Dict[str, Any]) -> bytes:
        """Generate simple text-based report when weasyprint is not available"""
        try:
            report_lines = []
            report_lines.append("=" * 60)
            report_lines.append("🛡️ MalwareShield Pro - Analysis Report")
            report_lines.append("=" * 60)
            report_lines.append("")
            
            # File Information
            report_lines.append("FILE INFORMATION")
            report_lines.append("-" * 20)
            report_lines.append(f"Filename: {results.get('filename', 'Unknown')}")
            report_lines.append(f"File Size: {results.get('file_size', 0):,} bytes")
            report_lines.append(f"File Type: {results.get('file_type', 'Unknown')}")
            report_lines.append(f"Analysis Time: {results.get('analysis_time', 'Unknown')[:19]}")
            report_lines.append("")
            
            # Hash Analysis
            report_lines.append("HASH ANALYSIS")
            report_lines.append("-" * 20)
            hashes = results.get('hashes', {})
            if hashes:
                report_lines.append(f"MD5: {hashes.get('md5', 'Not calculated')}")
                report_lines.append(f"SHA1: {hashes.get('sha1', 'Not calculated')}")
                report_lines.append(f"SHA256: {hashes.get('sha256', 'Not calculated')}")
            else:
                report_lines.append("Hash calculation failed or not available.")
            report_lines.append("")
            
            # Threat Assessment
            report_lines.append("THREAT ASSESSMENT")
            report_lines.append("-" * 20)
            threat_data = results.get('threat_assessment', {})
            if threat_data:
                level = threat_data.get('level', 'UNKNOWN')
                score = threat_data.get('score', 0)
                confidence = threat_data.get('confidence', 0)
                report_lines.append(f"Threat Level: {level} ({score}/100)")
                report_lines.append(f"Confidence: {confidence:.1f}%")
                
                reasoning = threat_data.get('reasoning', [])
                if reasoning:
                    report_lines.append("Assessment Reasoning:")
                    for reason in reasoning[:5]:
                        report_lines.append(f"• {reason}")
            report_lines.append("")
            
            # Technical Details
            report_lines.append("TECHNICAL DETAILS")
            report_lines.append("-" * 20)
            report_lines.append(f"Entropy: {results.get('entropy', 0):.3f}")
            report_lines.append(f"Extracted Strings: {len(results.get('strings', []))}")
            report_lines.append(f"Suspicious Indicators: {len(results.get('suspicious_indicators', []))}")
            report_lines.append("")
            
            # Suspicious Indicators
            indicators = results.get('suspicious_indicators', [])
            if indicators:
                report_lines.append("SUSPICIOUS INDICATORS")
                report_lines.append("-" * 20)
                for indicator in indicators[:10]:
                    report_lines.append(f"• {indicator}")
                report_lines.append("")
            
            # VirusTotal Results
            vt_results = results.get('virustotal', {})
            if vt_results and vt_results.get('available'):
                report_lines.append("VIRUSTOTAL RESULTS")
                report_lines.append("-" * 20)
                detections = vt_results.get('detections', 0)
                total_engines = vt_results.get('total_engines', 0)
                report_lines.append(f"Detection Rate: {detections}/{total_engines} engines")
                
                if detections > 0:
                    detected_engines = vt_results.get('detected_engines', [])
                    report_lines.append("Detected by:")
                    for engine in detected_engines[:5]:
                        report_lines.append(f"• {engine}")
                report_lines.append("")
            
            # Recommendations
            report_lines.append("RECOMMENDATIONS")
            report_lines.append("-" * 20)
            threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
            recommendations = self._get_recommendations(threat_level, results)
            for rec in recommendations:
                report_lines.append(f"• {rec}")
            report_lines.append("")
            
            # Footer
            report_lines.append("=" * 60)
            report_lines.append("Built with 🛡️ by [Vishwas] - MalwareShield Pro")
            report_lines.append("=" * 60)
            
            return '\n'.join(report_lines).encode('utf-8')
            
        except Exception as e:
            return self._generate_error_report(f"Text report generation error: {str(e)}")
    
    def _generate_error_report(self, error_message: str) -> bytes:
        """Generate simple error report"""
        error_report = f"""
MalwareShield Pro - Report Generation Error

An error occurred while generating the report:

{error_message}

Please try again or contact support.

Built with 🛡️ by [Vishwas]
"""
        return error_report.encode('utf-8')
    
    def _get_recommendations(self, threat_level: str, results: Dict) -> list:
        """Generate recommendations based on threat level"""
        recommendations = []
        
        if threat_level == 'CRITICAL':
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Isolate the system immediately",
                "Do not execute or open this file under any circumstances",
                "Run a full system scan with updated antivirus software",
                "Consider restoring from a clean backup if file was executed",
                "Report to security team and consider forensic analysis"
            ])
        elif threat_level == 'HIGH':
            recommendations.extend([
                "HIGH RISK: Do not execute this file",
                "Quarantine the file immediately",
                "Scan the system with multiple antivirus engines",
                "Monitor system for suspicious activities",
                "Consider professional malware analysis"
            ])
        elif threat_level == 'MEDIUM':
            recommendations.extend([
                "MODERATE RISK: Exercise caution with this file",
                "Do not execute without proper sandboxing",
                "Consider additional analysis with specialized tools",
                "Monitor file behavior if execution is necessary",
                "Keep system and antivirus software updated"
            ])
        elif threat_level == 'LOW':
            recommendations.extend([
                "LOW RISK: File appears relatively safe but remain vigilant",
                "Consider scanning with additional antivirus engines",
                "Monitor system after execution",
                "Ensure system security measures are in place"
            ])
        else:  # CLEAN or UNKNOWN
            recommendations.extend([
                "File appears clean based on current analysis",
                "No immediate threats detected",
                "Continue normal security practices",
                "Keep antivirus software updated"
            ])
        
        # Add general recommendations
        recommendations.extend([
            "Always maintain updated antivirus software",
            "Regular system backups are recommended",
            "Practice safe computing habits"
        ])
        
        return recommendations
    
    def export_json(self, results: Dict[str, Any]) -> str:
        """Export results as JSON"""
        try:
            # Clean results for JSON serialization
            clean_results = self._clean_for_json(results)
            
            # Add metadata
            clean_results['report_metadata'] = {
                'generated_at': datetime.now().isoformat(),
                'generator': 'MalwareShield Pro',
                'version': '1.0',
                'format': 'json'
            }
            
            return json.dumps(clean_results, indent=2, ensure_ascii=False)
            
        except Exception as e:
            return json.dumps({
                'error': f'JSON export failed: {str(e)}',
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'MalwareShield Pro',
                    'version': '1.0',
                    'format': 'json'
                }
            }, indent=2)
    
    def _clean_for_json(self, data: Any) -> Any:
        """Clean data for JSON serialization"""
        if isinstance(data, dict):
            return {k: self._clean_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._clean_for_json(item) for item in data]
        elif isinstance(data, bytes):
            return data.decode('utf-8', errors='ignore')
        elif hasattr(data, '__dict__'):
            return str(data)
        else:
            return data
    
    def generate_json_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate JSON report from analysis results
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            JSON report as string
        """
        try:
            # Clean and validate the analysis results
            cleaned_results = self._clean_analysis_results(analysis_results)
            
            # Add report metadata
            cleaned_results['report_metadata'] = {
                'generated_at': datetime.now().isoformat(),
                'generator': 'MalwareShield Pro',
                'version': '1.0',
                'format': 'json',
                'threat_level': cleaned_results.get('threat_assessment', {}).get('level', 'UNKNOWN'),
                'recommendations': self._get_recommendations(
                    cleaned_results.get('threat_assessment', {}).get('level', 'UNKNOWN'), 
                    cleaned_results
                )
            }
            
            return json.dumps(cleaned_results, indent=2, ensure_ascii=False)
            
        except Exception as e:
            return json.dumps({
                'error': f'JSON report generation failed: {str(e)}',
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'MalwareShield Pro',
                    'version': '1.0',
                    'format': 'json'
                }
            }, indent=2)
