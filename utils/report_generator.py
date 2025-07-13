"""
Report Generator Module

Provides comprehensive PDF and JSON report generation capabilities for malware
analysis results with professional formatting and detailed visualizations.
"""

import json
from datetime import datetime
from typing import Dict, Any, List
import io
import base64

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white, red, green, orange
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Image as ReportLabImage
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class ReportGenerator:
    """Professional report generator for malware analysis results"""
    
    def __init__(self):
        """Initialize the report generator"""
        self.styles = self._create_styles() if REPORTLAB_AVAILABLE else None
    
    def generate_report(self, results: Dict[str, Any]) -> bytes:
        """Generate a comprehensive PDF report
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            bytes: PDF report data
        """
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(results).encode('utf-8')
        
        try:
            # Create PDF buffer
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page(results))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(results))
            story.append(PageBreak())
            
            # File information
            story.extend(self._create_file_information(results))
            
            # Analysis details
            story.extend(self._create_analysis_details(results))
            
            # VirusTotal results if available
            if 'virustotal' in results:
                story.append(PageBreak())
                story.extend(self._create_virustotal_section(results))
            
            # Patterns and IOCs
            if 'patterns' in results:
                story.append(PageBreak())
                story.extend(self._create_patterns_section(results))
            
            # Recommendations
            story.append(PageBreak())
            story.extend(self._create_recommendations(results))
            
            # Build PDF
            doc.build(story)
            pdf_data = buffer.getvalue()
            buffer.close()
            
            return pdf_data
            
        except Exception as e:
            # Fallback to text report
            return self._generate_text_report(results, error=str(e)).encode('utf-8')
    
    def export_json(self, results: Dict[str, Any]) -> str:
        """Export results as formatted JSON
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            str: Formatted JSON string
        """
        try:
            # Create a clean copy for export
            export_data = self._prepare_json_export(results)
            return json.dumps(export_data, indent=2, default=self._json_serializer)
        except Exception as e:
            return json.dumps({
                'error': f'JSON export failed: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }, indent=2)
    
    def _create_styles(self):
        """Create custom styles for the PDF report"""
        if not REPORTLAB_AVAILABLE:
            return None
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=HexColor('#2c3e50')
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=12,
            textColor=HexColor('#34495e'),
            borderWidth=1,
            borderColor=HexColor('#bdc3c7'),
            borderPadding=5
        ))
        
        styles.add(ParagraphStyle(
            name='ThreatHigh',
            parent=styles['Normal'],
            fontSize=14,
            textColor=HexColor('#e74c3c'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            borderWidth=2,
            borderColor=HexColor('#e74c3c'),
            borderPadding=10
        ))
        
        styles.add(ParagraphStyle(
            name='ThreatMedium',
            parent=styles['Normal'],
            fontSize=14,
            textColor=HexColor('#f39c12'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            borderWidth=2,
            borderColor=HexColor('#f39c12'),
            borderPadding=10
        ))
        
        styles.add(ParagraphStyle(
            name='ThreatLow',
            parent=styles['Normal'],
            fontSize=14,
            textColor=HexColor('#27ae60'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            borderWidth=2,
            borderColor=HexColor('#27ae60'),
            borderPadding=10
        ))
        
        return styles
    
    def _create_title_page(self, results: Dict[str, Any]) -> List:
        """Create the title page for the report"""
        story = []
        
        # Title
        title = Paragraph("🛡️ MalwareShield Pro", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        subtitle = Paragraph("Comprehensive Malware Analysis Report", self.styles['Heading2'])
        story.append(subtitle)
        story.append(Spacer(1, 30))
        
        # File information
        file_info = results.get('file_info', {})
        filename = file_info.get('filename', 'Unknown')
        
        info_data = [
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Analyzed File:', filename],
            ['Scan Type:', results.get('scan_type', 'Unknown').title()],
            ['File Size:', self._format_file_size(file_info.get('size', 0))],
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6'))
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 50))
        
        # Threat level summary
        threat_info = results.get('threat_assessment', {})
        threat_level = threat_info.get('level', 'UNKNOWN')
        threat_score = threat_info.get('score', 0)
        
        threat_style = self._get_threat_style(threat_level)
        threat_text = f"THREAT LEVEL: {threat_level} (Score: {threat_score}/100)"
        threat_para = Paragraph(threat_text, self.styles[threat_style])
        
        story.append(threat_para)
        
        return story
    
    def _create_executive_summary(self, results: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        # Analysis overview
        file_info = results.get('file_info', {})
        threat_info = results.get('threat_assessment', {})
        
        summary_text = f"""
        This report presents the comprehensive analysis results for the file 
        "{file_info.get('filename', 'Unknown')}". The analysis was performed using 
        MalwareShield Pro's advanced detection capabilities.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Key findings
        story.append(Paragraph("Key Findings:", self.styles['Heading3']))
        
        findings = []
        
        # Threat level
        threat_level = threat_info.get('level', 'UNKNOWN')
        threat_score = threat_info.get('score', 0)
        findings.append(f"• Threat Level: {threat_level} ({threat_score}/100)")
        
        # File type
        analysis = results.get('analysis', {})
        file_type = analysis.get('file_type', 'Unknown')
        findings.append(f"• File Type: {file_type}")
        
        # Entropy
        entropy = analysis.get('entropy', 0)
        findings.append(f"• File Entropy: {entropy:.2f}")
        
        # Patterns
        patterns = results.get('patterns', {})
        total_patterns = sum(len(matches) for matches in patterns.values())
        findings.append(f"• Suspicious Patterns: {total_patterns} detected")
        
        # VirusTotal
        vt_results = results.get('virustotal', {})
        if 'stats' in vt_results:
            stats = vt_results['stats']
            malicious = stats.get('malicious', 0)
            total = stats.get('total', 0)
            findings.append(f"• VirusTotal Detection: {malicious}/{total} engines")
        
        for finding in findings:
            story.append(Paragraph(finding, self.styles['Normal']))
        
        story.append(Spacer(1, 12))
        
        # Recommendations preview
        recommendations = self._get_recommendations(results)
        if recommendations:
            story.append(Paragraph("Primary Recommendation:", self.styles['Heading3']))
            story.append(Paragraph(recommendations[0], self.styles['Normal']))
        
        return story
    
    def _create_file_information(self, results: Dict[str, Any]) -> List:
        """Create file information section"""
        story = []
        
        story.append(Paragraph("File Information", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        file_info = results.get('file_info', {})
        hashes = file_info.get('hashes', {})
        
        # Basic information table
        basic_data = [
            ['Property', 'Value'],
            ['Filename', file_info.get('filename', 'Unknown')],
            ['File Size', self._format_file_size(file_info.get('size', 0))],
            ['File Type', results.get('analysis', {}).get('file_type', 'Unknown')],
            ['Analysis Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ]
        
        basic_table = Table(basic_data, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
        ]))
        
        story.append(basic_table)
        story.append(Spacer(1, 20))
        
        # Hash values table
        if hashes:
            story.append(Paragraph("Hash Values", self.styles['Heading3']))
            
            hash_data = [['Hash Type', 'Value']]
            for hash_type, hash_value in hashes.items():
                hash_data.append([hash_type.upper(), hash_value])
            
            hash_table = Table(hash_data, colWidths=[1.5*inch, 4.5*inch])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
            ]))
            
            story.append(hash_table)
        
        return story
    
    def _create_analysis_details(self, results: Dict[str, Any]) -> List:
        """Create detailed analysis section"""
        story = []
        
        story.append(Paragraph("Technical Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        analysis = results.get('analysis', {})
        
        # Entropy analysis
        entropy = analysis.get('entropy', 0)
        story.append(Paragraph("Entropy Analysis", self.styles['Heading3']))
        
        entropy_text = f"File entropy: {entropy:.2f}"
        if entropy > 7.5:
            entropy_text += " (HIGH - Possible encryption/packing detected)"
        elif entropy < 1.0:
            entropy_text += " (LOW - Likely text or structured data)"
        else:
            entropy_text += " (NORMAL - Typical entropy range)"
        
        story.append(Paragraph(entropy_text, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # String analysis
        strings = analysis.get('strings', [])
        if strings:
            story.append(Paragraph("String Analysis", self.styles['Heading3']))
            story.append(Paragraph(f"Extracted {len(strings)} printable strings", self.styles['Normal']))
            
            # Show sample strings (first 10)
            sample_strings = strings[:10]
            if sample_strings:
                story.append(Paragraph("Sample strings:", self.styles['Normal']))
                for i, string_val in enumerate(sample_strings, 1):
                    # Truncate long strings
                    display_string = string_val[:100] + "..." if len(string_val) > 100 else string_val
                    story.append(Paragraph(f"{i}. {display_string}", self.styles['Normal']))
        
        return story
    
    def _create_virustotal_section(self, results: Dict[str, Any]) -> List:
        """Create VirusTotal results section"""
        story = []
        
        story.append(Paragraph("VirusTotal Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        vt_results = results.get('virustotal', {})
        
        if 'error' in vt_results:
            story.append(Paragraph(f"VirusTotal Error: {vt_results['error']}", self.styles['Normal']))
            return story
        
        # Detection statistics
        stats = vt_results.get('stats', {})
        if stats:
            stats_data = [
                ['Detection Category', 'Count'],
                ['Malicious', str(stats.get('malicious', 0))],
                ['Suspicious', str(stats.get('suspicious', 0))],
                ['Clean', str(stats.get('harmless', 0))],
                ['Undetected', str(stats.get('undetected', 0))],
                ['Total Engines', str(stats.get('total', 0))]
            ]
            
            stats_table = Table(stats_data, colWidths=[2*inch, 1*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
            ]))
            
            story.append(stats_table)
            story.append(Spacer(1, 20))
        
        # Detection details (show only positive detections)
        scans = vt_results.get('scans', {})
        if scans:
            positive_detections = {
                engine: result for engine, result in scans.items()
                if result.get('result') and result.get('result') != 'Clean'
            }
            
            if positive_detections:
                story.append(Paragraph("Positive Detections", self.styles['Heading3']))
                
                detection_data = [['Engine', 'Detection', 'Version']]
                for engine, result in positive_detections.items():
                    detection_data.append([
                        engine,
                        result.get('result', 'Unknown'),
                        result.get('version', 'N/A')
                    ])
                
                detection_table = Table(detection_data, colWidths=[2*inch, 2.5*inch, 1.5*inch])
                detection_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e74c3c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
                ]))
                
                story.append(detection_table)
        
        return story
    
    def _create_patterns_section(self, results: Dict[str, Any]) -> List:
        """Create patterns and IOCs section"""
        story = []
        
        story.append(Paragraph("Indicators of Compromise (IOCs)", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        patterns = results.get('patterns', {})
        
        if not patterns:
            story.append(Paragraph("No suspicious patterns detected.", self.styles['Normal']))
            return story
        
        for category, matches in patterns.items():
            if matches:
                story.append(Paragraph(f"{category.replace('_', ' ').title()} ({len(matches)} found)", self.styles['Heading3']))
                
                # Limit displayed matches to avoid overly long reports
                display_matches = matches[:20]
                for match in display_matches:
                    story.append(Paragraph(f"• {match}", self.styles['Normal']))
                
                if len(matches) > 20:
                    story.append(Paragraph(f"... and {len(matches) - 20} more", self.styles['Normal']))
                
                story.append(Spacer(1, 12))
        
        return story
    
    def _create_recommendations(self, results: Dict[str, Any]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        recommendations = self._get_recommendations(results)
        
        for i, recommendation in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
            story.append(Spacer(1, 6))
        
        return story
    
    def _get_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        threat_info = results.get('threat_assessment', {})
        threat_level = threat_info.get('level', 'UNKNOWN')
        
        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.append("IMMEDIATE ACTION REQUIRED: Quarantine this file immediately and perform a full system scan.")
            recommendations.append("Do not execute or open this file under any circumstances.")
            recommendations.append("Report this file to your security team and consider forensic analysis.")
        elif threat_level == 'MEDIUM':
            recommendations.append("Exercise caution: This file shows suspicious characteristics that warrant further investigation.")
            recommendations.append("Consider running additional analysis tools before execution.")
            recommendations.append("Monitor system behavior if this file has been executed.")
        elif threat_level == 'LOW':
            recommendations.append("File appears relatively safe but monitor for any unusual behavior.")
            recommendations.append("Consider verifying file source and digital signatures.")
        else:
            recommendations.append("File appears clean based on current analysis.")
            recommendations.append("Continue following standard security practices.")
        
        # Add specific recommendations based on findings
        analysis = results.get('analysis', {})
        entropy = analysis.get('entropy', 0)
        
        if entropy > 7.5:
            recommendations.append("High entropy detected - file may be packed or encrypted. Consider unpacking analysis.")
        
        patterns = results.get('patterns', {})
        if patterns.get('network'):
            recommendations.append("Network artifacts detected - monitor network traffic if file is executed.")
        
        if patterns.get('crypto'):
            recommendations.append("Cryptocurrency-related patterns detected - potential ransomware or cryptominer.")
        
        vt_results = results.get('virustotal', {})
        if vt_results.get('stats', {}).get('malicious', 0) > 5:
            recommendations.append("Multiple antivirus engines detected threats - treat as confirmed malware.")
        
        return recommendations[:10]  # Limit to 10 recommendations
    
    def _get_threat_style(self, threat_level: str) -> str:
        """Get appropriate style for threat level"""
        threat_styles = {
            'CRITICAL': 'ThreatHigh',
            'HIGH': 'ThreatHigh',
            'MEDIUM': 'ThreatMedium',
            'LOW': 'ThreatLow',
            'CLEAN': 'ThreatLow'
        }
        return threat_styles.get(threat_level, 'Normal')
    
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
    
    def _prepare_json_export(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare results for JSON export"""
        export_data = {
            'metadata': {
                'report_version': '1.0',
                'generator': 'MalwareShield Pro',
                'export_timestamp': datetime.now().isoformat(),
                'analysis_timestamp': results.get('timestamp', datetime.now().isoformat())
            },
            'file_information': results.get('file_info', {}),
            'analysis_results': results.get('analysis', {}),
            'threat_assessment': results.get('threat_assessment', {}),
            'patterns_detected': results.get('patterns', {}),
            'scan_type': results.get('scan_type', 'unknown')
        }
        
        # Add VirusTotal results if available
        if 'virustotal' in results:
            export_data['virustotal_results'] = results['virustotal']
        
        return export_data
    
    def _json_serializer(self, obj):
        """JSON serializer for non-standard types"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)
    
    def _generate_text_report(self, results: Dict[str, Any], error: str = None) -> str:
        """Generate a text-based report as fallback"""
        lines = []
        lines.append("=" * 80)
        lines.append("MALWARESHIELD PRO - ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        if error:
            lines.append(f"NOTE: PDF generation failed ({error}), using text format")
            lines.append("")
        
        # File information
        file_info = results.get('file_info', {})
        lines.append("FILE INFORMATION")
        lines.append("-" * 40)
        lines.append(f"Filename: {file_info.get('filename', 'Unknown')}")
        lines.append(f"File Size: {self._format_file_size(file_info.get('size', 0))}")
        lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        # Threat assessment
        threat_info = results.get('threat_assessment', {})
        lines.append("THREAT ASSESSMENT")
        lines.append("-" * 40)
        lines.append(f"Threat Level: {threat_info.get('level', 'UNKNOWN')}")
        lines.append(f"Threat Score: {threat_info.get('score', 0)}/100")
        lines.append("")
        
        # Analysis summary
        analysis = results.get('analysis', {})
        lines.append("ANALYSIS SUMMARY")
        lines.append("-" * 40)
        lines.append(f"File Type: {analysis.get('file_type', 'Unknown')}")
        lines.append(f"Entropy: {analysis.get('entropy', 0):.2f}")
        lines.append(f"Strings Extracted: {len(analysis.get('strings', []))}")
        lines.append("")
        
        # Patterns
        patterns = results.get('patterns', {})
        if patterns:
            lines.append("DETECTED PATTERNS")
            lines.append("-" * 40)
            for category, matches in patterns.items():
                if matches:
                    lines.append(f"{category.replace('_', ' ').title()}: {len(matches)} found")
            lines.append("")
        
        # VirusTotal results
        vt_results = results.get('virustotal', {})
        if vt_results and 'stats' in vt_results:
            stats = vt_results['stats']
            lines.append("VIRUSTOTAL RESULTS")
            lines.append("-" * 40)
            lines.append(f"Detection Ratio: {stats.get('malicious', 0)}/{stats.get('total', 0)}")
            lines.append(f"Malicious: {stats.get('malicious', 0)}")
            lines.append(f"Suspicious: {stats.get('suspicious', 0)}")
            lines.append(f"Clean: {stats.get('harmless', 0)}")
            lines.append("")
        
        # Recommendations
        recommendations = self._get_recommendations(results)
        if recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 40)
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return "\n".join(lines)
