import json
import pandas as pd
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    """Streamlit-compatible report generator"""
    
    def __init__(self):
        pass
        
    def generate_pdf_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """Generate text report as PDF alternative"""
        text_report = self._generate_text_report(analysis_results)
        return text_report.encode('utf-8')
    
    def generate_json_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate JSON report"""
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
    
    def generate_csv_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate CSV report"""
        summary_data = []
        
        # File info
        file_info = analysis_results.get('file_info', {})
        summary_data.append({'Category': 'File', 'Property': 'Name', 'Value': file_info.get('name', 'Unknown')})
        summary_data.append({'Category': 'File', 'Property': 'Size', 'Value': str(file_info.get('size', 0))})
        
        # Threat assessment
        threat = analysis_results.get('threat_assessment', {})
        summary_data.append({'Category': 'Threat', 'Property': 'Level', 'Value': threat.get('level', 'Unknown')})
        summary_data.append({'Category': 'Threat', 'Property': 'Score', 'Value': str(threat.get('score', 0))})
        
        # Hashes
        if 'hashes' in analysis_results:
            for algo, hash_val in analysis_results['hashes'].items():
                summary_data.append({'Category': 'Hash', 'Property': algo.upper(), 'Value': hash_val})
        
        df = pd.DataFrame(summary_data)
        return df.to_csv(index=False)
    
    def _generate_text_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate text report"""
        lines = ["=" * 60, "MALWARESHIELD PRO ANALYSIS REPORT", "=" * 60, ""]
        
        # File info
        file_info = analysis_results.get('file_info', {})
        lines.extend([
            "FILE INFORMATION:",
            f"Name: {file_info.get('name', 'Unknown')}",
            f"Size: {file_info.get('size', 0)} bytes",
            ""
        ])
        
        # Threat assessment
        threat = analysis_results.get('threat_assessment', {})
        lines.extend([
            "THREAT ASSESSMENT:",
            f"Level: {threat.get('level', 'Unknown')}",
            f"Score: {threat.get('score', 0)}/100",
            ""
        ])
        
        # Hashes
        if 'hashes' in analysis_results:
            lines.append("HASHES:")
            for algo, hash_val in analysis_results['hashes'].items():
                lines.append(f"{algo.upper()}: {hash_val}")
            lines.append("")
        
        # VirusTotal
        if 'virustotal' in analysis_results:
            vt = analysis_results['virustotal']
            lines.append("VIRUSTOTAL RESULTS:")
            if 'stats' in vt:
                stats = vt['stats']
                lines.append(f"Malicious: {stats.get('malicious', 0)}")
                lines.append(f"Total Engines: {stats.get('total', 0)}")
            lines.append("")
        
        lines.extend(["=" * 60, "Created by vishux777", "=" * 60])
        return "\n".join(lines)