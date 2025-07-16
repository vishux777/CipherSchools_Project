"""
Report Generator for MalwareShield Pro
Generates PDF and JSON reports from analysis results

Built with 🛡️ by [Vishwas]
"""

import json
import io
from datetime import datetime
from typing import Dict, Any, Optional

try:
    from fpdf import FPDF
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

class ReportGenerator:
    """Professional report generator for malware analysis"""
    
    def __init__(self):
        self.colors = {
            'CLEAN': '#28a745',
            'LOW': '#ffc107',
            'MEDIUM': '#fd7e14',
            'HIGH': '#dc3545',
            'CRITICAL': '#721c24'
        }
    
    def _get_threat_color(self, threat_level: str) -> str:
        """Get color for threat level"""
        return self.colors.get(threat_level, '#6c757d')
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """
        Generate PDF report from analysis results
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            PDF report as bytes
        """
        try:
            if FPDF_AVAILABLE:
                return self._generate_fpdf_report(analysis_results)
            else:
                return self._generate_simple_text_report(analysis_results)
        except Exception as e:
            return self._generate_error_report(str(e))
    
    def _generate_fpdf_report(self, results: Dict[str, Any]) -> bytes:
        """Generate PDF report using FPDF2"""
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font('Arial', 'B', 20)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 15, '🛡️ MalwareShield Pro', ln=True, align='C')
            
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Advanced Malware Analysis Report', ln=True, align='C')
            pdf.ln(10)
            
            # File Information
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, 'File Information', ln=True)
            pdf.ln(5)
            
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(0, 0, 0)
            
            filename = results.get('filename', 'Unknown')
            file_size = results.get('file_size', 0)
            file_type = results.get('file_type', 'Unknown')
            analysis_time = results.get('analysis_time', datetime.now().isoformat())
            
            pdf.cell(0, 6, f'Filename: {filename}', ln=True)
            pdf.cell(0, 6, f'File Size: {file_size:,} bytes', ln=True)
            pdf.cell(0, 6, f'File Type: {file_type}', ln=True)
            pdf.cell(0, 6, f'Analysis Time: {analysis_time[:19]}', ln=True)
            pdf.ln(10)
            
            # Hash Analysis
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, 'Hash Analysis', ln=True)
            pdf.ln(5)
            
            pdf.set_font('Arial', '', 9)
            pdf.set_text_color(0, 0, 0)
            
            hashes = results.get('hashes', {})
            if hashes:
                pdf.cell(0, 6, f"MD5: {hashes.get('md5', 'Not calculated')}", ln=True)
                pdf.cell(0, 6, f"SHA1: {hashes.get('sha1', 'Not calculated')}", ln=True)
                pdf.cell(0, 6, f"SHA256: {hashes.get('sha256', 'Not calculated')}", ln=True)
            else:
                pdf.cell(0, 6, 'Hash calculation failed or not available.', ln=True)
            pdf.ln(10)
            
            # Threat Assessment
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, 'Threat Assessment', ln=True)
            pdf.ln(5)
            
            threat_data = results.get('threat_assessment', {})
            if threat_data:
                level = threat_data.get('level', 'UNKNOWN')
                score = threat_data.get('score', 0)
                confidence = threat_data.get('confidence', 0)
                
                pdf.set_font('Arial', 'B', 11)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 8, f'Threat Level: {level} ({score}/100)', ln=True)
                pdf.cell(0, 8, f'Confidence: {confidence:.1f}%', ln=True)
                
                # Reasoning
                reasoning = threat_data.get('reasoning', [])
                if reasoning:
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 6, 'Assessment Reasoning:', ln=True)
                    for reason in reasoning[:5]:  # Limit to 5 reasons
                        pdf.cell(0, 5, f'• {reason}', ln=True)
            pdf.ln(10)
            
            # Technical Details
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, 'Technical Details', ln=True)
            pdf.ln(5)
            
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(0, 0, 0)
            
            entropy = results.get('entropy', 0)
            pdf.cell(0, 6, f'Entropy: {entropy:.3f}', ln=True)
            
            strings_count = len(results.get('strings', []))
            pdf.cell(0, 6, f'Extracted Strings: {strings_count}', ln=True)
            
            indicators_count = len(results.get('suspicious_indicators', []))
            pdf.cell(0, 6, f'Suspicious Indicators: {indicators_count}', ln=True)
            pdf.ln(10)
            
            # Suspicious Indicators
            indicators = results.get('suspicious_indicators', [])
            if indicators:
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(0, 102, 204)
                pdf.cell(0, 10, 'Suspicious Indicators', ln=True)
                pdf.ln(5)
                
                pdf.set_font('Arial', '', 9)
                pdf.set_text_color(0, 0, 0)
                
                for indicator in indicators[:10]:  # Limit to 10 indicators
                    pdf.cell(0, 5, f'• {indicator}', ln=True)
                pdf.ln(10)
            
            # VirusTotal Results
            vt_results = results.get('virustotal', {})
            if vt_results and vt_results.get('available'):
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(0, 102, 204)
                pdf.cell(0, 10, 'VirusTotal Results', ln=True)
                pdf.ln(5)
                
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(0, 0, 0)
                
                detections = vt_results.get('detections', 0)
                total_engines = vt_results.get('total_engines', 0)
                
                pdf.cell(0, 6, f'Detection Rate: {detections}/{total_engines} engines', ln=True)
                
                if detections > 0:
                    detected_engines = vt_results.get('detected_engines', [])
                    pdf.cell(0, 6, 'Detected by:', ln=True)
                    for engine in detected_engines[:5]:  # Limit to 5 engines
                        pdf.cell(0, 5, f'• {engine}', ln=True)
                pdf.ln(10)
            
            # Recommendations
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, 'Recommendations', ln=True)
            pdf.ln(5)
            
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(0, 0, 0)
            
            threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
            recommendations = self._get_recommendations(threat_level, results)
            
            for rec in recommendations:
                pdf.cell(0, 6, f'• {rec}', ln=True)
            pdf.ln(10)
            
            # Footer
            pdf.set_font('Arial', 'I', 8)
            pdf.set_text_color(128, 128, 128)
            pdf.cell(0, 10, 'Built with 🛡️ by [Vishwas] - MalwareShield Pro', ln=True, align='C')
            
            # Return PDF as bytes
            return pdf.output(dest='S').encode('latin-1')
            
        except Exception as e:
            return self._generate_error_report(f"FPDF generation error: {str(e)}")
    
    def _generate_simple_text_report(self, results: Dict[str, Any]) -> bytes:
        """Generate simple text-based report when FPDF is not available"""
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