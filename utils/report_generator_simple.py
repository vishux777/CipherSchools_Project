import json
import io
import base64
from datetime import datetime
from typing import Dict, Any
import pandas as pd

class ReportGenerator:
    """Generate downloadable reports in various formats (Streamlit-compatible)"""
    
    def __init__(self):
        self.reportlab_available = False
        
    def generate_pdf_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """Generate text-based PDF report (fallback without ReportLab)"""
        # Since ReportLab may cause deployment issues, return text report as bytes
        text_report = self._generate_text_report(analysis_results)
        return text_report.encode('utf-8')
    
    def generate_json_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        try:
            # Create a clean copy for JSON export
            report_data = {
                "report_info": {
                    "generator": "MalwareShield Pro",
                    "version": "2.0",
                    "generated_at": datetime.now().isoformat(),
                    "created_by": "vishux777"
                },
                "analysis_results": analysis_results
            }
            
            return json.dumps(report_data, indent=2, default=str)
            
        except Exception as e:
            return json.dumps({"error": f"Failed to generate JSON report: {str(e)}"})
    
    def generate_csv_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate CSV report"""
        try:
            # Create summary data for CSV
            summary_data = []
            
            # File information
            file_info = analysis_results.get('file_info', {})
            summary_data.append({
                'Category': 'File Info',
                'Property': 'Name',
                'Value': file_info.get('name', 'Unknown')
            })
            summary_data.append({
                'Category': 'File Info',
                'Property': 'Size',
                'Value': self._format_file_size(file_info.get('size', 0))
            })
            
            # Threat assessment
            threat_assessment = analysis_results.get('threat_assessment', {})
            summary_data.append({
                'Category': 'Threat Assessment',
                'Property': 'Level',
                'Value': threat_assessment.get('level', 'Unknown')
            })
            summary_data.append({
                'Category': 'Threat Assessment',
                'Property': 'Score',
                'Value': f"{threat_assessment.get('score', 0)}/100"
            })
            
            # Hashes
            if 'hashes' in analysis_results:
                hashes = analysis_results['hashes']
                for algo, hash_value in hashes.items():
                    summary_data.append({
                        'Category': 'Hash',
                        'Property': algo.upper(),
                        'Value': hash_value
                    })
            
            # Entropy
            if 'entropy' in analysis_results:
                summary_data.append({
                    'Category': 'Entropy',
                    'Property': 'Value',
                    'Value': f"{analysis_results['entropy']:.3f}"
                })
            
            # VirusTotal
            if 'virustotal' in analysis_results:
                vt_data = analysis_results['virustotal']
                if 'stats' in vt_data:
                    stats = vt_data['stats']
                    for key, value in stats.items():
                        summary_data.append({
                            'Category': 'VirusTotal',
                            'Property': key.title(),
                            'Value': str(value)
                        })
            
            # Convert to DataFrame and then CSV
            df = pd.DataFrame(summary_data)
            return df.to_csv(index=False)
            
        except Exception as e:
            return f"Error generating CSV report: {str(e)}"
    
    def _generate_text_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("🛡️ MALWARESHIELD PRO - COMPREHENSIVE ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # File information
        file_info = analysis_results.get('file_info', {})
        lines.append("📄 FILE INFORMATION")
        lines.append("-" * 30)
        lines.append(f"Name: {file_info.get('name', 'Unknown')}")
        lines.append(f"Size: {self._format_file_size(file_info.get('size', 0))}")
        lines.append(f"Analysis Date: {file_info.get('analysis_time', 'Unknown')[:19]}")
        lines.append("")
        
        # Threat assessment
        threat_assessment = analysis_results.get('threat_assessment', {})
        lines.append("🚨 THREAT ASSESSMENT")
        lines.append("-" * 30)
        lines.append(f"Threat Level: {threat_assessment.get('level', 'Unknown')}")
        lines.append(f"Risk Score: {threat_assessment.get('score', 0)}/100")
        
        risk_factors = threat_assessment.get('risk_factors', [])
        if risk_factors:
            lines.append("\nRisk Factors:")
            for factor in risk_factors:
                lines.append(f"• {factor}")
        lines.append("")
        
        # Hash analysis
        if 'hashes' in analysis_results:
            lines.append("🔍 HASH ANALYSIS")
            lines.append("-" * 30)
            hashes = analysis_results['hashes']
            for algo, hash_value in hashes.items():
                lines.append(f"{algo.upper()}: {hash_value}")
            lines.append("")
        
        # Entropy analysis
        if 'entropy' in analysis_results:
            lines.append("📊 ENTROPY ANALYSIS")
            lines.append("-" * 30)
            entropy = analysis_results['entropy']
            lines.append(f"Shannon Entropy: {entropy:.6f}")
            lines.append(f"Entropy Ratio: {(entropy/8)*100:.1f}% of maximum")
            lines.append(f"Interpretation: {self._get_entropy_interpretation(entropy)}")
            lines.append("")
        
        # VirusTotal results
        if 'virustotal' in analysis_results:
            lines.append("🌐 VIRUSTOTAL ANALYSIS")
            lines.append("-" * 30)
            vt_data = analysis_results['virustotal']
            
            if 'error' in vt_data:
                lines.append(f"Error: {vt_data['error']}")
            elif 'stats' in vt_data:
                stats = vt_data['stats']
                lines.append(f"Total Engines: {stats['total']}")
                lines.append(f"Malicious Detections: {stats['malicious']}")
                lines.append(f"Suspicious Detections: {stats['suspicious']}")
                lines.append(f"Clean Results: {stats['harmless']}")
                lines.append(f"Undetected: {stats['undetected']}")
                
                if stats['malicious'] > 0:
                    lines.append(f"\n⚠️  THREAT DETECTED by {stats['malicious']} engines!")
                else:
                    lines.append(f"\n✅ No threats detected by VirusTotal engines")
            lines.append("")
        
        # Pattern detection
        if 'patterns' in analysis_results:
            lines.append("🎯 PATTERN DETECTION")
            lines.append("-" * 30)
            patterns = analysis_results['patterns']
            
            for pattern_type, pattern_list in patterns.items():
                if pattern_list:
                    lines.append(f"\n{pattern_type.replace('_', ' ').title()} ({len(pattern_list)} found):")
                    for i, pattern in enumerate(pattern_list[:10]):  # Show first 10
                        lines.append(f"  {i+1}. {pattern}")
                    if len(pattern_list) > 10:
                        lines.append(f"  ... and {len(pattern_list) - 10} more")
            lines.append("")
        
        # String analysis
        if 'strings' in analysis_results:
            lines.append("📝 STRING ANALYSIS")
            lines.append("-" * 30)
            strings = analysis_results['strings']
            lines.append(f"Total Strings Extracted: {len(strings)}")
            
            if strings:
                lines.append(f"\nSample Strings (first 20):")
                for i, s in enumerate(strings[:20]):
                    lines.append(f"  {i+1}. {s}")
                
                if len(strings) > 20:
                    lines.append(f"  ... and {len(strings) - 20} more strings")
            lines.append("")
        
        # Behavioral analysis
        if 'behavioral' in analysis_results:
            lines.append("🧠 BEHAVIORAL ANALYSIS")
            lines.append("-" * 30)
            behavioral = analysis_results['behavioral']
            
            lines.append(f"Risk Score: {behavioral.get('risk_score', 0)}/100")
            
            indicators = behavioral.get('indicators', [])
            if indicators:
                lines.append(f"\nSecurity Indicators ({len(indicators)} found):")
                for indicator in indicators:
                    severity = indicator.get('severity', 'unknown').upper()
                    title = indicator.get('title', 'Unknown')
                    description = indicator.get('description', '')
                    lines.append(f"• [{severity}] {title}")
                    if description:
                        lines.append(f"  Description: {description}")
            
            capabilities = behavioral.get('capabilities', [])
            if capabilities:
                lines.append(f"\nDetected Capabilities ({len(capabilities)} found):")
                for capability in capabilities:
                    cap_name = capability.get('capability', 'Unknown')
                    risk_level = capability.get('risk_level', 'unknown').upper()
                    details = capability.get('details', '')
                    lines.append(f"• [{risk_level}] {cap_name}")
                    if details:
                        lines.append(f"  Details: {details}")
            lines.append("")
        
        # Footer
        lines.append("=" * 80)
        lines.append("REPORT GENERATED BY MALWARESHIELD PRO")
        lines.append("Created by vishux777")
        lines.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        import math
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    def _get_entropy_interpretation(self, entropy: float) -> str:
        """Get detailed entropy interpretation"""
        if entropy < 1:
            return "Very low entropy - highly structured/repetitive data"
        elif entropy < 3:
            return "Low entropy - structured data with some patterns"
        elif entropy < 5:
            return "Moderate entropy - mixed structured and random data"
        elif entropy < 7:
            return "High entropy - mostly random data or compressed"
        elif entropy < 7.5:
            return "Very high entropy - likely compressed or encrypted"
        else:
            return "Extremely high entropy - possibly packed malware or strong encryption"