import json
import io
import base64
from datetime import datetime
from typing import Dict, Any
import pandas as pd

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class ReportGenerator:
    """Generate downloadable reports in various formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet() if REPORTLAB_AVAILABLE else None
        
    def generate_pdf_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """Generate comprehensive PDF report"""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(analysis_results).encode('utf-8')
        
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            story = []
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=self.styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                spaceBefore=20,
                textColor=colors.darkgreen
            )
            
            # Title
            story.append(Paragraph("🛡️ MalwareShield Pro - Analysis Report", title_style))
            story.append(Spacer(1, 20))
            
            # File information
            file_info = analysis_results.get('file_info', {})
            story.append(Paragraph("📄 File Information", heading_style))
            
            file_data = [
                ['Property', 'Value'],
                ['File Name', file_info.get('name', 'Unknown')],
                ['File Size', self._format_file_size(file_info.get('size', 0))],
                ['Analysis Date', file_info.get('analysis_time', 'Unknown')[:19]],
                ['Analysis Version', 'MalwareShield Pro v2.0']
            ]
            
            file_table = Table(file_data, colWidths=[2*inch, 4*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(file_table)
            story.append(Spacer(1, 20))
            
            # Threat Assessment
            threat_assessment = analysis_results.get('threat_assessment', {})
            threat_level = threat_assessment.get('level', 'Unknown')
            threat_score = threat_assessment.get('score', 0)
            
            story.append(Paragraph("🚨 Threat Assessment", heading_style))
            
            threat_color = self._get_threat_color_reportlab(threat_level)
            threat_style = ParagraphStyle(
                'ThreatStyle',
                parent=self.styles['Normal'],
                fontSize=18,
                textColor=threat_color,
                alignment=TA_CENTER,
                spaceAfter=10
            )
            
            story.append(Paragraph(f"<b>THREAT LEVEL: {threat_level.upper()}</b>", threat_style))
            story.append(Paragraph(f"Risk Score: {threat_score}/100", self.styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Hash Analysis
            if 'hashes' in analysis_results:
                story.append(Paragraph("🔍 Hash Analysis", heading_style))
                hashes = analysis_results['hashes']
                
                hash_data = [
                    ['Algorithm', 'Hash Value'],
                    ['MD5', hashes.get('md5', 'N/A')],
                    ['SHA1', hashes.get('sha1', 'N/A')],
                    ['SHA256', hashes.get('sha256', 'N/A')]
                ]
                
                hash_table = Table(hash_data, colWidths=[1*inch, 5*inch])
                hash_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(hash_table)
                story.append(Spacer(1, 15))
            
            # Entropy Analysis
            if 'entropy' in analysis_results:
                story.append(Paragraph("📊 Entropy Analysis", heading_style))
                entropy = analysis_results['entropy']
                
                entropy_data = [
                    ['Metric', 'Value', 'Interpretation'],
                    ['File Entropy', f"{entropy:.3f}", self._get_entropy_interpretation_short(entropy)],
                    ['Max Entropy', '8.000', 'Theoretical maximum'],
                    ['Entropy Ratio', f"{(entropy/8)*100:.1f}%", 'Percentage of maximum']
                ]
                
                entropy_table = Table(entropy_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
                entropy_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(entropy_table)
                story.append(Spacer(1, 15))
            
            # VirusTotal Results
            if 'virustotal' in analysis_results:
                story.append(Paragraph("🌐 VirusTotal Analysis", heading_style))
                vt_data = analysis_results['virustotal']
                
                if 'stats' in vt_data:
                    stats = vt_data['stats']
                    
                    vt_summary = [
                        ['Detection Category', 'Count', 'Percentage'],
                        ['Malicious', str(stats['malicious']), f"{(stats['malicious']/stats['total']*100):.1f}%"],
                        ['Suspicious', str(stats['suspicious']), f"{(stats['suspicious']/stats['total']*100):.1f}%"],
                        ['Clean', str(stats['harmless']), f"{(stats['harmless']/stats['total']*100):.1f}%"],
                        ['Undetected', str(stats['undetected']), f"{(stats['undetected']/stats['total']*100):.1f}%"],
                        ['Total Engines', str(stats['total']), '100%']
                    ]
                    
                    vt_table = Table(vt_summary, colWidths=[2*inch, 1*inch, 1*inch])
                    vt_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    story.append(vt_table)
                    story.append(Spacer(1, 15))
            
            # Pattern Detection
            if 'patterns' in analysis_results:
                story.append(Paragraph("🎯 Pattern Detection", heading_style))
                patterns = analysis_results['patterns']
                
                pattern_summary = [
                    ['Pattern Type', 'Count', 'Examples']
                ]
                
                for pattern_type, pattern_list in patterns.items():
                    count = len(pattern_list)
                    examples = ', '.join(pattern_list[:3]) if pattern_list else 'None'
                    if len(examples) > 50:
                        examples = examples[:47] + "..."
                    
                    pattern_summary.append([
                        pattern_type.title(),
                        str(count),
                        examples
                    ])
                
                pattern_table = Table(pattern_summary, colWidths=[1.5*inch, 0.8*inch, 3.7*inch])
                pattern_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(pattern_table)
                story.append(Spacer(1, 20))
            
            # Footer
            story.append(PageBreak())
            story.append(Spacer(1, 50))
            
            footer_style = ParagraphStyle(
                'Footer',
                parent=self.styles['Normal'],
                fontSize=10,
                alignment=TA_CENTER,
                textColor=colors.grey
            )
            
            story.append(Paragraph("Generated by MalwareShield Pro", footer_style))
            story.append(Paragraph("Created by vishux777", footer_style))
            story.append(Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            return buffer.getvalue()
            
        except Exception as e:
            # Fallback to text report
            return self._generate_text_report(analysis_results).encode('utf-8')
    
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
        """Generate simple text report as fallback"""
        lines = []
        lines.append("=" * 60)
        lines.append("🛡️ MALWARESHIELD PRO - ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append("")
        
        # File information
        file_info = analysis_results.get('file_info', {})
        lines.append("📄 FILE INFORMATION")
        lines.append("-" * 20)
        lines.append(f"Name: {file_info.get('name', 'Unknown')}")
        lines.append(f"Size: {self._format_file_size(file_info.get('size', 0))}")
        lines.append(f"Analysis Date: {file_info.get('analysis_time', 'Unknown')[:19]}")
        lines.append("")
        
        # Threat assessment
        threat_assessment = analysis_results.get('threat_assessment', {})
        lines.append("🚨 THREAT ASSESSMENT")
        lines.append("-" * 20)
        lines.append(f"Level: {threat_assessment.get('level', 'Unknown')}")
        lines.append(f"Score: {threat_assessment.get('score', 0)}/100")
        lines.append("")
        
        # Hashes
        if 'hashes' in analysis_results:
            lines.append("🔍 HASH ANALYSIS")
            lines.append("-" * 15)
            hashes = analysis_results['hashes']
            for algo, hash_value in hashes.items():
                lines.append(f"{algo.upper()}: {hash_value}")
            lines.append("")
        
        # Entropy
        if 'entropy' in analysis_results:
            lines.append("📊 ENTROPY ANALYSIS")
            lines.append("-" * 18)
            lines.append(f"Entropy: {analysis_results['entropy']:.3f}")
            lines.append("")
        
        # VirusTotal
        if 'virustotal' in analysis_results:
            lines.append("🌐 VIRUSTOTAL RESULTS")
            lines.append("-" * 21)
            vt_data = analysis_results['virustotal']
            if 'stats' in vt_data:
                stats = vt_data['stats']
                lines.append(f"Total Engines: {stats['total']}")
                lines.append(f"Malicious: {stats['malicious']}")
                lines.append(f"Suspicious: {stats['suspicious']}")
                lines.append(f"Clean: {stats['harmless']}")
            lines.append("")
        
        lines.append("=" * 60)
        lines.append("Generated by MalwareShield Pro")
        lines.append("Created by vishux777")
        lines.append(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    def _get_threat_color_reportlab(self, threat_level: str):
        """Get ReportLab color for threat level"""
        if not REPORTLAB_AVAILABLE:
            return None
        
        color_map = {
            "Low": colors.green,
            "Medium": colors.orange,
            "High": colors.red,
            "Critical": colors.darkred
        }
        return color_map.get(threat_level, colors.black)
    
    def _get_entropy_interpretation_short(self, entropy: float) -> str:
        """Get short entropy interpretation for reports"""
        if entropy > 7.5:
            return "Very High - Likely encrypted"
        elif entropy > 7:
            return "High - May be compressed"
        elif entropy > 6:
            return "Elevated - Some compression"
        elif entropy > 4:
            return "Normal - Typical range"
        else:
            return "Low - Highly structured"
