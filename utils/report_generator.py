"""
Report Generator for MalwareShield Pro - FIXED VERSION
Generates PDF and JSON reports from analysis results using HTML-to-PDF conversion
Built with 🛡️ by [Vishwas]
"""

import json
import io
from datetime import datetime
from typing import Dict, Any, Optional, Union
import os
import tempfile

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
        return self.colors.get(threat_level.upper(), '#6c757d')
    
    def generate_pdf_report(self, analysis_results: Dict[str, Any], output_path: Optional[str] = None) -> Union[bytes, str]:
        """
        Generate PDF report from analysis results using HTML-to-PDF conversion
        
        Args:
            analysis_results: Complete analysis results
            output_path: Optional path to save the PDF file
            
        Returns:
            PDF report as bytes if output_path is None, otherwise returns the file path
        """
        try:
            # Clean and validate the analysis results
            cleaned_results = self._clean_analysis_results(analysis_results)
            
            if WEASYPRINT_AVAILABLE:
                pdf_bytes = self._generate_html_to_pdf_report(cleaned_results)
            else:
                # Fallback to text report saved as PDF-like format
                pdf_bytes = self._generate_text_as_pdf_fallback(cleaned_results)
            
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(pdf_bytes)
                return output_path
            
            return pdf_bytes
                
        except Exception as e:
            error_pdf = self._generate_error_pdf(str(e))
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(error_pdf)
                return output_path
            return error_pdf
    
    def generate_text_report(self, analysis_results: Dict[str, Any], output_path: Optional[str] = None) -> Union[str, str]:
        """
        Generate text report from analysis results
        
        Args:
            analysis_results: Complete analysis results
            output_path: Optional path to save the text file
            
        Returns:
            Text report as string if output_path is None, otherwise returns the file path
        """
        try:
            # Clean and validate the analysis results
            cleaned_results = self._clean_analysis_results(analysis_results)
            
            report_text = self._generate_text_report_content(cleaned_results)
            
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                return output_path
            
            return report_text
                
        except Exception as e:
            error_text = self._generate_error_text(str(e))
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(error_text)
                return output_path
            return error_text
    
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
            # Generate HTML content
            html_content = self._generate_html_content(results)
            
            # Create HTML document with proper base URL
            html_doc = HTML(string=html_content, base_url='.')
            
            # Generate PDF with optimized settings
            pdf_bytes = html_doc.write_pdf(
                optimize_size=('fonts', 'images'),
                presentational_hints=True
            )
            
            # Validate PDF output more reliably
            if pdf_bytes and len(pdf_bytes) > 200:
                # Check for PDF header (should start with %PDF)
                if pdf_bytes.startswith(b'%PDF'):
                    return pdf_bytes
                else:
                    print("Warning: Generated PDF doesn't have proper header, falling back to text")
                    return self._generate_text_as_pdf_fallback(results)
            else:
                print("Warning: PDF generation failed, falling back to text")
                return self._generate_text_as_pdf_fallback(results)
                
        except Exception as e:
            print(f"PDF generation error: {e}")
            return self._generate_text_as_pdf_fallback(results)
    
    def _generate_html_content(self, results: Dict[str, Any]) -> str:
        """Generate HTML content for PDF conversion"""
        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
        threat_color = self._get_threat_color(threat_level)
        
        def safe_str(value, max_length=None):
            """Convert value to safe string for HTML"""
            if value is None:
                return 'Unknown'
            str_value = str(value).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
            if max_length and len(str_value) > max_length:
                return str_value[:max_length] + '...'
            return str_value
        
        # Format analysis time
        analysis_time = results.get('analysis_time', '')
        if analysis_time:
            try:
                # Try to parse and format the datetime
                if 'T' in analysis_time:
                    dt = datetime.fromisoformat(analysis_time.replace('Z', '+00:00'))
                    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    formatted_time = analysis_time[:19]
            except:
                formatted_time = str(analysis_time)[:19]
        else:
            formatted_time = 'Unknown'
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MalwareShield Pro Report</title>
    <style>
        @page {{
            size: A4;
            margin: 1in;
        }}
        body {{ 
            font-family: Arial, sans-serif; 
            margin: 0;
            padding: 0;
            line-height: 1.4;
            color: #333;
        }}
        .header {{ 
            text-align: center; 
            margin-bottom: 30px; 
            border-bottom: 3px solid #0066cc;
            padding-bottom: 20px;
        }}
        .header h1 {{
            color: #0066cc;
            margin: 0;
            font-size: 24px;
        }}
        .header h2 {{
            color: #666;
            margin: 10px 0;
            font-size: 18px;
        }}
        .section {{ 
            margin-bottom: 25px;
            page-break-inside: avoid;
        }}
        .section h3 {{ 
            color: #0066cc; 
            border-bottom: 2px solid #0066cc; 
            padding-bottom: 5px;
            margin-bottom: 15px;
            font-size: 16px;
        }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-bottom: 15px;
        }}
        td {{ 
            padding: 8px 10px; 
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }}
        td:first-child {{ 
            width: 30%; 
            font-weight: bold;
            color: #555;
        }}
        .threat-level {{ 
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
            color: white; 
            background-color: {threat_color};
            text-align: center;
            font-weight: bold;
        }}
        ul {{ 
            margin: 10px 0;
            padding-left: 20px;
        }}
        li {{
            margin-bottom: 5px;
        }}
        .hash {{ 
            font-family: 'Courier New', monospace; 
            font-size: 11px; 
            word-break: break-all;
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-style: italic;
        }}
        .highlight {{
            background-color: #fff3cd;
            padding: 2px 4px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ MalwareShield Pro</h1>
        <h2>Malware Analysis Report</h2>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h3>📄 File Information</h3>
        <table>
            <tr><td>Filename:</td><td>{safe_str(results.get('filename'))}</td></tr>
            <tr><td>File Size:</td><td>{results.get('file_size', 0):,} bytes</td></tr>
            <tr><td>File Type:</td><td>{safe_str(results.get('file_type'))}</td></tr>
            <tr><td>Analysis Time:</td><td>{formatted_time}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h3>🔍 Hash Analysis</h3>
        <table>"""
        
        hashes = results.get('hashes', {})
        if hashes:
            for hash_type in ['md5', 'sha1', 'sha256']:
                hash_value = hashes.get(hash_type)
                if hash_value:
                    html += f'<tr><td>{hash_type.upper()}:</td><td class="hash">{safe_str(hash_value)}</td></tr>'
                else:
                    html += f'<tr><td>{hash_type.upper()}:</td><td>Not calculated</td></tr>'
        else:
            html += '<tr><td colspan="2">Hash calculation not available</td></tr>'
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h3>⚠️ Threat Assessment</h3>"""
        
        threat_data = results.get('threat_assessment', {})
        if threat_data:
            level = threat_data.get('level', 'UNKNOWN')
            score = threat_data.get('score', 0)
            confidence = threat_data.get('confidence', 0)
            
            html += f"""
        <div class="threat-level">
            Threat Level: {level} ({score}/100)<br>
            Confidence: {confidence:.1f}%
        </div>"""
            
            reasoning = threat_data.get('reasoning', [])
            if reasoning:
                html += '<h4>Assessment Reasoning:</h4><ul>'
                for reason in reasoning[:10]:  # Limit to prevent overflow
                    html += f'<li>{safe_str(reason, 200)}</li>'
                html += '</ul>'
        else:
            html += '<p>No threat assessment data available.</p>'
        
        html += """
    </div>
    
    <div class="section">
        <h3>🔧 Technical Details</h3>
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
        <h3>🚨 Suspicious Indicators</h3>
        <ul>"""
            for indicator in indicators[:15]:  # Limit to prevent overflow
                html += f'<li>{safe_str(indicator, 150)}</li>'
            if len(indicators) > 15:
                html += f'<li><em>... and {len(indicators) - 15} more indicators</em></li>'
            html += '</ul></div>'
        
        # VirusTotal Results
        vt_results = results.get('virustotal', {})
        if vt_results and vt_results.get('available'):
            detections = vt_results.get('detections', 0)
            total_engines = vt_results.get('total_engines', 0)
            
            html += f"""
    <div class="section">
        <h3>🦠 VirusTotal Results</h3>
        <table>
            <tr><td>Detection Rate:</td><td class="highlight">{detections}/{total_engines} engines</td></tr>
        </table>"""
            
            if detections > 0:
                detected_engines = vt_results.get('detected_engines', [])
                if detected_engines:
                    html += '<h4>Detected by:</h4><ul>'
                    for engine in detected_engines[:10]:  # Limit to prevent overflow
                        html += f'<li>{safe_str(engine)}</li>'
                    if len(detected_engines) > 10:
                        html += f'<li><em>... and {len(detected_engines) - 10} more engines</em></li>'
                    html += '</ul>'
            html += '</div>'
        
        # Recommendations
        recommendations = self._get_recommendations(threat_level, results)
        html += """
    <div class="section">
        <h3>💡 Recommendations</h3>
        <ul>"""
        for rec in recommendations:
            html += f'<li>{safe_str(rec, 200)}</li>'
        
        html += """
        </ul>
    </div>
    
    <div class="footer">
        <p>Built with 🛡️ by [Vishwas] - MalwareShield Pro v1.0</p>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_text_as_pdf_fallback(self, results: Dict[str, Any]) -> bytes:
        """Generate text report as PDF fallback when weasyprint fails"""
        text_content = self._generate_text_report_content(results)
        
        # Simple HTML wrapper for text content
        html_fallback = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MalwareShield Pro Report</title>
    <style>
        body {{ font-family: 'Courier New', monospace; margin: 20px; white-space: pre-wrap; }}
    </style>
</head>
<body>
{text_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')}
</body>
</html>"""
        
        try:
            if WEASYPRINT_AVAILABLE:
                html_doc = HTML(string=html_fallback, base_url='.')
                return html_doc.write_pdf()
            else:
                # If weasyprint is not available, return text as bytes
                return text_content.encode('utf-8')
        except:
            return text_content.encode('utf-8')
    
    def _generate_text_report_content(self, results: Dict[str, Any]) -> str:
        """Generate text report content"""
        try:
            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append("🛡️ MalwareShield Pro - Malware Analysis Report")
            report_lines.append("=" * 80)
            report_lines.append("")
            report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("")
            
            # File Information
            report_lines.append("📄 FILE INFORMATION")
            report_lines.append("-" * 40)
            report_lines.append(f"Filename: {results.get('filename', 'Unknown')}")
            report_lines.append(f"File Size: {results.get('file_size', 0):,} bytes")
            report_lines.append(f"File Type: {results.get('file_type', 'Unknown')}")
            
            # Format analysis time
            analysis_time = results.get('analysis_time', 'Unknown')
            if analysis_time and analysis_time != 'Unknown':
                try:
                    if 'T' in analysis_time:
                        dt = datetime.fromisoformat(analysis_time.replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        formatted_time = str(analysis_time)[:19]
                except:
                    formatted_time = str(analysis_time)[:19]
            else:
                formatted_time = 'Unknown'
            
            report_lines.append(f"Analysis Time: {formatted_time}")
            report_lines.append("")
            
            # Hash Analysis
            report_lines.append("🔍 HASH ANALYSIS")
            report_lines.append("-" * 40)
            hashes = results.get('hashes', {})
            if hashes:
                for hash_type in ['md5', 'sha1', 'sha256']:
                    hash_value = hashes.get(hash_type)
                    if hash_value:
                        report_lines.append(f"{hash_type.upper()}: {hash_value}")
                    else:
                        report_lines.append(f"{hash_type.upper()}: Not calculated")
            else:
                report_lines.append("Hash calculation failed or not available.")
            report_lines.append("")
            
            # Threat Assessment
            report_lines.append("⚠️ THREAT ASSESSMENT")
            report_lines.append("-" * 40)
            threat_data = results.get('threat_assessment', {})
            if threat_data:
                level = threat_data.get('level', 'UNKNOWN')
                score = threat_data.get('score', 0)
                confidence = threat_data.get('confidence', 0)
                report_lines.append(f"Threat Level: {level} ({score}/100)")
                report_lines.append(f"Confidence: {confidence:.1f}%")
                report_lines.append("")
                
                reasoning = threat_data.get('reasoning', [])
                if reasoning:
                    report_lines.append("Assessment Reasoning:")
                    for reason in reasoning[:10]:  # Limit to prevent overflow
                        report_lines.append(f"• {reason}")
            else:
                report_lines.append("No threat assessment data available.")
            report_lines.append("")
            
            # Technical Details
            report_lines.append("🔧 TECHNICAL DETAILS")
            report_lines.append("-" * 40)
            report_lines.append(f"Entropy: {results.get('entropy', 0):.3f}")
            report_lines.append(f"Extracted Strings: {len(results.get('strings', []))}")
            report_lines.append(f"Suspicious Indicators: {len(results.get('suspicious_indicators', []))}")
            report_lines.append("")
            
            # Suspicious Indicators
            indicators = results.get('suspicious_indicators', [])
            if indicators:
                report_lines.append("🚨 SUSPICIOUS INDICATORS")
                report_lines.append("-" * 40)
                for indicator in indicators[:15]:  # Limit to prevent overflow
                    report_lines.append(f"• {indicator}")
                if len(indicators) > 15:
                    report_lines.append(f"• ... and {len(indicators) - 15} more indicators")
                report_lines.append("")
            
            # VirusTotal Results
            vt_results = results.get('virustotal', {})
            if vt_results and vt_results.get('available'):
                report_lines.append("🦠 VIRUSTOTAL RESULTS")
                report_lines.append("-" * 40)
                detections = vt_results.get('detections', 0)
                total_engines = vt_results.get('total_engines', 0)
                report_lines.append(f"Detection Rate: {detections}/{total_engines} engines")
                report_lines.append("")
                
                if detections > 0:
                    detected_engines = vt_results.get('detected_engines', [])
                    if detected_engines:
                        report_lines.append("Detected by:")
                        for engine in detected_engines[:10]:  # Limit to prevent overflow
                            report_lines.append(f"• {engine}")
                        if len(detected_engines) > 10:
                            report_lines.append(f"• ... and {len(detected_engines) - 10} more engines")
                report_lines.append("")
            
            # Recommendations
            report_lines.append("💡 RECOMMENDATIONS")
            report_lines.append("-" * 40)
            threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
            recommendations = self._get_recommendations(threat_level, results)
            for rec in recommendations:
                report_lines.append(f"• {rec}")
            report_lines.append("")
            
            # Footer
            report_lines.append("=" * 80)
            report_lines.append("Built with 🛡️ by [Vishwas] - MalwareShield Pro v1.0")
            report_lines.append("=" * 80)
            
            return '\n'.join(report_lines)
            
        except Exception as e:
            return self._generate_error_text(f"Text report generation error: {str(e)}")
    
    def _generate_error_pdf(self, error_message: str) -> bytes:
        """Generate PDF error report"""
        error_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MalwareShield Pro - Error Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .error {{ background-color: #f8d7da; color: #721c24; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>🛡️ MalwareShield Pro</h1>
    <h2>Report Generation Error</h2>
    
    <div class="error">
        <h3>An error occurred while generating the report:</h3>
        <p>{error_message}</p>
        <p>Please try again or contact support.</p>
    </div>
    
    <p><em>Built with 🛡️ by [Vishwas] - MalwareShield Pro</em></p>
</body>
</html>"""
        
        try:
            if WEASYPRINT_AVAILABLE:
                html_doc = HTML(string=error_html, base_url='.')
                return html_doc.write_pdf()
            else:
                return error_html.encode('utf-8')
        except:
            return error_html.encode('utf-8')
    
    def _generate_error_text(self, error_message: str) -> str:
        """Generate simple error text report"""
        return f"""
MalwareShield Pro - Report Generation Error

An error occurred while generating the report:

{error_message}

Please try again or contact support.

Built with 🛡️ by [Vishwas] - MalwareShield Pro
"""
    
    def _get_recommendations(self, threat_level: str, results: Dict) -> list:
        """Generate recommendations based on threat level"""
        recommendations = []
        
        threat_level = threat_level.upper()
        
        if threat_level == 'CRITICAL':
            recommendations.extend([
                "🚨 IMMEDIATE ACTION REQUIRED: Isolate the system immediately",
                "⛔ Do not execute or open this file under any circumstances",
                "🔍 Run a full system scan with updated antivirus software",
                "💾 Consider restoring from a clean backup if file was executed",
                "📞 Report to security team and consider forensic analysis",
                "🔒 Change all passwords and monitor for suspicious activities"
            ])
        elif threat_level == 'HIGH':
            recommendations.extend([
                "⚠️ HIGH RISK: Do not execute this file",
                "🔒 Quarantine the file immediately",
                "🛡️ Scan the system with multiple antivirus engines",
                "👁️ Monitor system for suspicious activities",
                "🔬 Consider professional malware analysis",
                "🚫 Isolate affected systems from network"
            ])
        elif threat_level == 'MEDIUM':
            recommendations.extend([
                "⚡ MODERATE RISK: Exercise caution with this file",
                "🏠 Do not execute without proper sandboxing",
                "🔧 Consider additional analysis with specialized tools",
                "📊 Monitor file behavior if execution is necessary",
                "🔄 Keep system and antivirus software updated",
                "🛡️ Implement additional security measures"
            ])
        elif threat_level == 'LOW':
            recommendations.extend([
                "✅ LOW RISK: File appears relatively safe but remain vigilant",
                "🔍 Consider scanning with additional antivirus engines",
                "👁️ Monitor system after execution",
                "🔒 Ensure system security measures are in place",
                "📈 Regular security assessments recommended"
            ])
        else:  # CLEAN or UNKNOWN
            recommendations.extend([
                "✅ File appears clean based on current analysis",
                "🔍 No immediate threats detected",
                "📋 Continue normal security practices",
                "🔄 Keep antivirus software updated",
                "🛡️ Maintain regular security monitoring"
            ])
        
        # Add general recommendations
        recommendations.extend([
            "🔄 Always maintain updated antivirus software",
            "💾 Regular system backups are recommended",
            "🎯 Practice safe computing habits",
            "🔐 Use strong, unique passwords",
            "📚 Stay informed about latest security threats"
        ])
        
        return recommendations
    
    def generate_json_report(self, analysis_results: Dict[str, Any], output_path: Optional[str] = None) -> Union[str, str]:
        """
        Generate JSON report from analysis results
        
        Args:
            analysis_results: Complete analysis results
            output_path: Optional path to save the JSON file
            
        Returns:
            JSON report as string if output_path is None, otherwise returns the file path
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
            
            # Clean data for JSON serialization
            json_data = self._clean_for_json(cleaned_results)
            
            json_content = json.dumps(json_data, indent=2, ensure_ascii=False)
            
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                return output_path
            
            return json_content
            
        except Exception as e:
            error_json = json.dumps({
                'error': f'JSON report generation failed: {str(e)}',
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'MalwareShield Pro',
                    'version': '1.0',
                    'format': 'json'
                }
            }, indent=2)
            
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(error_json)
                return output_path
            
            return error_json
    
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

    # Legacy methods for backward compatibility
    def generate_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """
        Legacy method for backward compatibility
        Generate PDF report from analysis results
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            PDF report as bytes
        """
        return self.generate_pdf_report(analysis_results)
    
    def export_json(self, results: Dict[str, Any]) -> str:
        """
        Legacy method for backward compatibility
        Export results as JSON
        
        Args:
            results: Analysis results
            
        Returns:
            JSON string
        """
        return self.generate_json_report(results)

# Usage examples and utility functions
def save_report_to_file(report_generator: ReportGenerator, analysis_results: Dict[str, Any], 
                       filename_base: str, formats: list = ['pdf', 'txt', 'json']) -> Dict[str, str]:
    """
    Save reports in multiple formats
    
    Args:
        report_generator: ReportGenerator instance
        analysis_results: Analysis results
        filename_base: Base filename (without extension)
        formats: List of formats to generate ('pdf', 'txt', 'json')
        
    Returns:
        Dictionary mapping format to saved file path
    """
    saved_files = {}
    
    for fmt in formats:
        try:
            if fmt == 'pdf':
                filepath = f"{filename_base}.pdf"
                report_generator.generate_pdf_report(analysis_results, filepath)
                saved_files['pdf'] = filepath
            elif fmt == 'txt':
                filepath = f"{filename_base}.txt"
                report_generator.generate_text_report(analysis_results, filepath)
                saved_files['txt'] = filepath
            elif fmt == 'json':
                filepath = f"{filename_base}.json"
                report_generator.generate_json_report(analysis_results, filepath)
                saved_files['json'] = filepath
        except Exception as e:
            print(f"Error saving {fmt} report: {e}")
            saved_files[fmt] = f"Error: {str(e)}"
    
    return saved_files

def create_sample_analysis_results() -> Dict[str, Any]:
    """Create sample analysis results for testing"""
    return {
        'filename': 'suspicious_file.exe',
        'file_size': 1024000,
        'file_type': 'PE32 executable',
        'analysis_time': datetime.now().isoformat(),
        'hashes': {
            'md5': 'abcdef1234567890abcdef1234567890',
            'sha1': 'abcdef1234567890abcdef1234567890abcdef12',
            'sha256': 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        },
        'threat_assessment': {
            'level': 'HIGH',
            'score': 85,
            'confidence': 92.5,
            'reasoning': [
                'Suspicious API calls detected',
                'Obfuscated strings found',
                'Network communication attempts',
                'Registry modification patterns'
            ]
        },
        'entropy': 7.2,
        'strings': ['suspicious_string1', 'suspicious_string2', 'malware_indicator'],
        'suspicious_indicators': [
            'CreateProcess API call',
            'Registry key modification',
            'Network socket creation',
            'File system access'
        ],
        'virustotal': {
            'available': True,
            'detections': 45,
            'total_engines': 70,
            'detected_engines': ['Engine1', 'Engine2', 'Engine3', 'Engine4', 'Engine5']
        }
    }

# Example usage
if __name__ == "__main__":
    # Create report generator
    generator = ReportGenerator()
    
    # Create sample data
    sample_data = create_sample_analysis_results()
    
    # Generate reports
    try:
        print("Generating reports...")
        
        # Save all formats
        saved_files = save_report_to_file(
            generator, 
            sample_data, 
            'malware_analysis_report',
            ['pdf', 'txt', 'json']
        )
        
        print("Reports generated successfully:")
        for fmt, path in saved_files.items():
            print(f"  {fmt.upper()}: {path}")
            
    except Exception as e:
        print(f"Error generating reports: {e}")