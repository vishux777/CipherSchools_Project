"""
Report Generator for MalwareShield Pro
Generates PDF and JSON reports from analysis results

Built with 🛡️ by [Vishwas]
"""

import json
import io
from datetime import datetime
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

class ReportGenerator:
    """Professional report generator for malware analysis"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#0066CC'),
            alignment=TA_CENTER,
            spaceAfter=30,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#0066CC'),
            alignment=TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0066CC'),
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))
        
        # Threat level styles
        self.styles.add(ParagraphStyle(
            name='ThreatCritical',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.white,
            backColor=colors.red,
            alignment=TA_CENTER,
            borderPadding=10,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ThreatHigh',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.white,
            backColor=colors.orange,
            alignment=TA_CENTER,
            borderPadding=10,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ThreatMedium',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.white,
            backColor=colors.yellow,
            alignment=TA_CENTER,
            borderPadding=10,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ThreatLow',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.white,
            backColor=colors.green,
            alignment=TA_CENTER,
            borderPadding=10,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ThreatClean',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.white,
            backColor=colors.green,
            alignment=TA_CENTER,
            borderPadding=10,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> bytes:
        """
        Generate PDF report from analysis results
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            PDF report as bytes
        """
        try:
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
            story.extend(self._build_title_page(analysis_results))
            
            # Executive summary
            story.extend(self._build_executive_summary(analysis_results))
            
            # File information
            story.extend(self._build_file_information(analysis_results))
            
            # Hash analysis
            story.extend(self._build_hash_analysis(analysis_results))
            
            # Threat assessment
            story.extend(self._build_threat_assessment(analysis_results))
            
            # Technical details
            story.extend(self._build_technical_details(analysis_results))
            
            # Pattern analysis
            story.extend(self._build_pattern_analysis(analysis_results))
            
            # VirusTotal results
            story.extend(self._build_virustotal_results(analysis_results))
            
            # Recommendations
            story.extend(self._build_recommendations(analysis_results))
            
            # Build PDF
            doc.build(story)
            
            # Return PDF bytes
            buffer.seek(0)
            return buffer.read()
            
        except Exception as e:
            # Return error message as simple PDF
            return self._generate_error_report(str(e))
    
    def _build_title_page(self, results: Dict) -> list:
        """Build title page"""
        story = []
        
        # Main title
        story.append(Paragraph("🛡️ MalwareShield Pro", self.styles['CustomTitle']))
        story.append(Spacer(1, 12))
        
        # Subtitle
        story.append(Paragraph("Advanced Malware Analysis Report", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 30))
        
        # File information
        filename = results.get('filename', 'Unknown')
        story.append(Paragraph(f"<b>File:</b> {filename}", self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Analysis date
        analysis_time = results.get('analysis_time', datetime.now().isoformat())
        story.append(Paragraph(f"<b>Analysis Date:</b> {analysis_time[:19]}", self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Threat level preview
        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
        threat_score = results.get('threat_assessment', {}).get('score', 0)
        
        threat_style = f'Threat{threat_level.title()}'
        if threat_style in self.styles:
            story.append(Paragraph(f"Threat Level: {threat_level} ({threat_score}/100)", self.styles[threat_style]))
        else:
            story.append(Paragraph(f"<b>Threat Level:</b> {threat_level} ({threat_score}/100)", self.styles['Normal']))
        
        story.append(Spacer(1, 50))
        
        # Credits
        story.append(Paragraph("<b>Built with 🛡️ by [Vishwas]</b>", self.styles['Normal']))
        story.append(Paragraph("MalwareShield Pro - Advanced Threat Detection Platform", self.styles['Normal']))
        
        story.append(PageBreak())
        return story
    
    def _build_executive_summary(self, results: Dict) -> list:
        """Build executive summary"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Generate summary based on results
        filename = results.get('filename', 'Unknown')
        file_size = results.get('file_size', 0)
        threat_data = results.get('threat_assessment', {})
        threat_level = threat_data.get('level', 'UNKNOWN')
        threat_score = threat_data.get('score', 0)
        
        summary_text = f"""
        This report presents the analysis results for the file '{filename}' 
        ({file_size:,} bytes) conducted using MalwareShield Pro's advanced static analysis engine.
        
        <b>Key Findings:</b>
        • Threat Level: {threat_level} ({threat_score}/100)
        • File Size: {file_size:,} bytes
        • Entropy Level: {results.get('entropy', 0):.2f}
        • Suspicious Indicators: {len(results.get('suspicious_indicators', []))}
        
        The analysis employed multiple detection mechanisms including hash analysis, 
        entropy calculation, string extraction, pattern matching, and threat scoring algorithms.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        return story
    
    def _build_file_information(self, results: Dict) -> list:
        """Build file information section"""
        story = []
        
        story.append(Paragraph("File Information", self.styles['SectionHeader']))
        
        # Create table with file details
        file_data = [
            ['Property', 'Value'],
            ['Filename', results.get('filename', 'Unknown')],
            ['File Size', f"{results.get('file_size', 0):,} bytes"],
            ['File Type', results.get('file_type', 'Unknown')],
            ['Analysis Time', results.get('analysis_time', 'Unknown')[:19]],
            ['Entropy', f"{results.get('entropy', 0):.3f}"]
        ]
        
        file_table = Table(file_data, colWidths=[2*inch, 3*inch])
        file_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0066CC')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(file_table)
        story.append(Spacer(1, 20))
        
        return story
    
    def _build_hash_analysis(self, results: Dict) -> list:
        """Build hash analysis section"""
        story = []
        
        story.append(Paragraph("Hash Analysis", self.styles['SectionHeader']))
        
        hashes = results.get('hashes', {})
        if hashes:
            hash_data = [
                ['Hash Type', 'Value'],
                ['MD5', hashes.get('md5', 'Not calculated')],
                ['SHA1', hashes.get('sha1', 'Not calculated')],
                ['SHA256', hashes.get('sha256', 'Not calculated')]
            ]
            
            hash_table = Table(hash_data, colWidths=[1.5*inch, 4*inch])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0066CC')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Courier')
            ]))
            
            story.append(hash_table)
        else:
            story.append(Paragraph("Hash calculation failed or not available.", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        return story
    
    def _build_threat_assessment(self, results: Dict) -> list:
        """Build threat assessment section"""
        story = []
        
        story.append(Paragraph("Threat Assessment", self.styles['SectionHeader']))
        
        threat_data = results.get('threat_assessment', {})
        if threat_data:
            level = threat_data.get('level', 'UNKNOWN')
            score = threat_data.get('score', 0)
            confidence = threat_data.get('confidence', 0)
            
            # Threat level display
            threat_style = f'Threat{level.title()}'
            if threat_style in self.styles:
                story.append(Paragraph(f"THREAT LEVEL: {level}", self.styles[threat_style]))
            else:
                story.append(Paragraph(f"<b>Threat Level:</b> {level}", self.styles['Normal']))
            
            story.append(Spacer(1, 12))
            
            # Threat details
            threat_details = f"""
            <b>Threat Score:</b> {score}/100<br/>
            <b>Confidence Level:</b> {confidence:.1%}<br/>
            <b>Risk Assessment:</b> {self._get_risk_description(level)}
            """
            
            story.append(Paragraph(threat_details, self.styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Reasoning
            reasons = threat_data.get('reasons', [])
            if reasons:
                story.append(Paragraph("<b>Detection Reasons:</b>", self.styles['Normal']))
                for reason in reasons:
                    story.append(Paragraph(f"• {reason}", self.styles['Normal']))
        else:
            story.append(Paragraph("Threat assessment not available.", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        return story
    
    def _build_technical_details(self, results: Dict) -> list:
        """Build technical details section"""
        story = []
        
        story.append(Paragraph("Technical Analysis", self.styles['SectionHeader']))
        
        # Entropy analysis
        entropy = results.get('entropy', 0)
        entropy_text = f"""
        <b>Entropy Analysis:</b><br/>
        File entropy: {entropy:.3f}<br/>
        {self._get_entropy_description(entropy)}
        """
        story.append(Paragraph(entropy_text, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # String analysis
        strings = results.get('strings', [])
        string_text = f"""
        <b>String Analysis:</b><br/>
        Extracted strings: {len(strings)}<br/>
        Notable findings: {self._analyze_strings(strings)}
        """
        story.append(Paragraph(string_text, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Suspicious indicators
        indicators = results.get('suspicious_indicators', [])
        if indicators:
            story.append(Paragraph("<b>Suspicious Indicators:</b>", self.styles['Normal']))
            for indicator in indicators[:10]:  # Limit to 10
                story.append(Paragraph(f"• {indicator}", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        return story
    
    def _build_pattern_analysis(self, results: Dict) -> list:
        """Build pattern analysis section"""
        story = []
        
        story.append(Paragraph("Pattern Analysis", self.styles['SectionHeader']))
        
        patterns = results.get('patterns', {})
        if patterns:
            # Create pattern summary table
            pattern_data = [['Pattern Type', 'Count', 'Examples']]
            
            for pattern_type, items in patterns.items():
                if items:
                    examples = ', '.join(items[:3])  # Show first 3 examples
                    if len(items) > 3:
                        examples += f' ... (+{len(items)-3} more)'
                    pattern_data.append([pattern_type.replace('_', ' ').title(), str(len(items)), examples])
            
            if len(pattern_data) > 1:
                pattern_table = Table(pattern_data, colWidths=[1.5*inch, 0.8*inch, 3*inch])
                pattern_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0066CC')),
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
            else:
                story.append(Paragraph("No significant patterns detected.", self.styles['Normal']))
        else:
            story.append(Paragraph("Pattern analysis not available.", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        return story
    
    def _build_virustotal_results(self, results: Dict) -> list:
        """Build VirusTotal results section"""
        story = []
        
        story.append(Paragraph("VirusTotal Analysis", self.styles['SectionHeader']))
        
        vt_results = results.get('virustotal_results')
        if vt_results and 'error' not in vt_results:
            positive = vt_results.get('positive_scans', 0)
            total = vt_results.get('total_scans', 0)
            
            vt_text = f"""
            <b>Detection Results:</b><br/>
            Positive detections: {positive}/{total}<br/>
            Detection ratio: {positive/total:.1%} of engines<br/>
            Scan date: {vt_results.get('scan_date', 'Unknown')}
            """
            
            story.append(Paragraph(vt_text, self.styles['Normal']))
        else:
            error_msg = vt_results.get('error', 'VirusTotal scan not performed') if vt_results else 'VirusTotal scan not performed'
            story.append(Paragraph(f"VirusTotal: {error_msg}", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        return story
    
    def _build_recommendations(self, results: Dict) -> list:
        """Build recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        
        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
        
        recommendations = self._get_recommendations(threat_level, results)
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # Footer
        story.append(Paragraph("Built with 🛡️ by [Vishwas] - MalwareShield Pro", self.styles['Normal']))
        
        return story
    
    def _get_risk_description(self, level: str) -> str:
        """Get risk description for threat level"""
        descriptions = {
            'CLEAN': "File appears to be clean with no significant threats detected.",
            'LOW': "File shows minimal suspicious characteristics. Low risk of malware.",
            'MEDIUM': "File contains suspicious patterns that warrant further investigation.",
            'HIGH': "File shows multiple suspicious indicators suggesting potential malware.",
            'CRITICAL': "File is highly suspicious with severe threat indicators. Immediate action required."
        }
        return descriptions.get(level, "Unable to determine risk level.")
    
    def _get_entropy_description(self, entropy: float) -> str:
        """Get entropy description"""
        if entropy > 7.5:
            return "Extremely high entropy indicates heavy compression or encryption."
        elif entropy > 7.0:
            return "Very high entropy suggests packed or encrypted content."
        elif entropy > 6.5:
            return "High entropy may indicate compression or obfuscation."
        elif entropy > 5.0:
            return "Moderate entropy levels are within normal range."
        else:
            return "Low entropy suggests structured, readable content."
    
    def _analyze_strings(self, strings: list) -> str:
        """Analyze strings for notable characteristics"""
        if not strings:
            return "No readable strings found."
        
        total = len(strings)
        if total > 1000:
            return f"Large number of strings ({total}) may indicate complex functionality."
        elif total < 10:
            return f"Very few strings ({total}) may suggest obfuscation or binary content."
        else:
            return f"Normal string count ({total}) detected."
    
    def _get_recommendations(self, threat_level: str, results: Dict) -> list:
        """Generate recommendations based on threat level"""
        base_recommendations = [
            "Verify file source and legitimacy before execution",
            "Scan with multiple antivirus engines for confirmation",
            "Monitor system behavior if file execution is necessary"
        ]
        
        level_specific = {
            'CLEAN': [
                "File appears safe but continue monitoring",
                "Regular system scans recommended"
            ],
            'LOW': [
                "Exercise caution but file is likely safe",
                "Consider sandboxed execution for testing"
            ],
            'MEDIUM': [
                "Investigate file further before use",
                "Consider quarantine until verification complete"
            ],
            'HIGH': [
                "Strongly recommend avoiding execution",
                "Quarantine file immediately",
                "Report to security team if in corporate environment"
            ],
            'CRITICAL': [
                "DO NOT EXECUTE - High malware probability",
                "Isolate system if file was already executed",
                "Perform full system scan and cleanup",
                "Report to security team immediately"
            ]
        }
        
        recommendations = base_recommendations.copy()
        recommendations.extend(level_specific.get(threat_level, []))
        
        return recommendations
    
    def _generate_error_report(self, error_message: str) -> bytes:
        """Generate simple error report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        
        story = [
            Paragraph("MalwareShield Pro - Report Generation Error", self.styles['Title']),
            Spacer(1, 20),
            Paragraph(f"Error: {error_message}", self.styles['Normal']),
            Spacer(1, 20),
            Paragraph("Built with 🛡️ by [Vishwas]", self.styles['Normal'])
        ]
        
        doc.build(story)
        buffer.seek(0)
        return buffer.read()
    
    def export_json(self, results: Dict[str, Any]) -> str:
        """Export results as JSON"""
        try:
            # Clean up results for JSON serialization
            cleaned_results = self._clean_for_json(results)
            
            # Add metadata
            export_data = {
                'metadata': {
                    'exported_at': datetime.now().isoformat(),
                    'tool': 'MalwareShield Pro',
                    'version': '2.0',
                    'author': 'Built with 🛡️ by [Vishwas]'
                },
                'analysis_results': cleaned_results
            }
            
            return json.dumps(export_data, indent=2, default=str)
            
        except Exception as e:
            return json.dumps({
                'error': f'JSON export failed: {str(e)}',
                'metadata': {
                    'exported_at': datetime.now().isoformat(),
                    'tool': 'MalwareShield Pro'
                }
            }, indent=2)
    
    def _clean_for_json(self, data: Any) -> Any:
        """Clean data for JSON serialization"""
        if isinstance(data, dict):
            return {k: self._clean_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._clean_for_json(item) for item in data]
        elif isinstance(data, (str, int, float, bool)):
            return data
        else:
            return str(data)
