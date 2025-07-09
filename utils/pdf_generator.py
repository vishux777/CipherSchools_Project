import io
import base64
from datetime import datetime
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, red, orange, green, grey
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus import Image as ReportLabImage
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import plotly.graph_objects as go
import plotly.io as pio

class PDFGenerator:
    """PDF report generator for malware analysis results"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the PDF"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1f4e79'),
            alignment=TA_CENTER
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=HexColor('#2e75b6'),
            borderWidth=1,
            borderColor=HexColor('#2e75b6'),
            borderPadding=5
        ))
        
        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=15,
            textColor=HexColor('#4472c4')
        ))
        
        # Warning style
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=red,
            backColor=HexColor('#ffe6e6'),
            borderWidth=1,
            borderColor=red,
            borderPadding=10,
            spaceAfter=10
        ))
        
        # Success style
        self.styles.add(ParagraphStyle(
            name='Success',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=green,
            backColor=HexColor('#e6ffe6'),
            borderWidth=1,
            borderColor=green,
            borderPadding=10,
            spaceAfter=10
        ))
    
    def generate_report(self, report_data: Dict[Any, Any]) -> Optional[io.BytesIO]:
        """Generate comprehensive PDF report"""
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch)
            
            # Build content
            story = []
            
            # Title page
            self._add_title_page(story, report_data)
            
            # Executive summary
            self._add_executive_summary(story, report_data)
            
            # File information
            if report_data.get('file_info'):
                self._add_file_information(story, report_data['file_info'])
            
            # Static analysis results
            if report_data.get('static_results') and report_data['options']['include_static']:
                self._add_static_analysis(story, report_data['static_results'])
            
            # VirusTotal results
            if report_data.get('vt_results') and report_data['options']['include_virustotal']:
                self._add_virustotal_analysis(story, report_data['vt_results'])
            
            # Threat assessment
            self._add_threat_assessment(story, report_data)
            
            # Recommendations
            self._add_recommendations(story, report_data)
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            
            return buffer
            
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return None
    
    def _add_title_page(self, story, report_data):
        """Add title page to the report"""
        story.append(Spacer(1, 2*inch))
        
        # Main title
        title = Paragraph("🛡️ MalwareShield Pro", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.3*inch))
        
        # Subtitle
        subtitle = Paragraph("Comprehensive Malware Analysis Report", self.styles['Heading1'])
        subtitle.style.alignment = TA_CENTER
        story.append(subtitle)
        story.append(Spacer(1, 1*inch))
        
        # Report information
        if report_data.get('file_info'):
            file_name = report_data['file_info']['name']
            file_info = Paragraph(f"<b>File Analyzed:</b> {file_name}", self.styles['Normal'])
            file_info.style.alignment = TA_CENTER
            story.append(file_info)
            story.append(Spacer(1, 0.2*inch))
        
        # Generation time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        time_info = Paragraph(f"<b>Report Generated:</b> {timestamp}", self.styles['Normal'])
        time_info.style.alignment = TA_CENTER
        story.append(time_info)
        
        story.append(PageBreak())
    
    def _add_executive_summary(self, story, report_data):
        """Add executive summary section"""
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        
        # Calculate overall threat level
        threat_level = self._calculate_overall_threat_level(report_data)
        threat_color = self._get_threat_color(threat_level)
        
        # Threat level summary
        threat_summary = f"""
        <para align=center>
        <b>Overall Threat Level: <font color="{threat_color}">{threat_level.upper()}</font></b>
        </para>
        """
        story.append(Paragraph(threat_summary, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Analysis summary
        summary_text = self._generate_executive_summary_text(report_data, threat_level)
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
    
    def _add_file_information(self, story, file_info):
        """Add file information section"""
        story.append(Paragraph("File Information", self.styles['CustomHeading']))
        
        # Create file info table
        file_data = [
            ['Property', 'Value'],
            ['File Name', file_info.get('name', 'Unknown')],
            ['File Size', self._format_file_size(file_info.get('size', 0))],
            ['File Type', file_info.get('type', 'Unknown')]
        ]
        
        table = Table(file_data, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#4472c4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
    
    def _add_static_analysis(self, story, static_results):
        """Add static analysis results section"""
        story.append(Paragraph("Static Analysis Results", self.styles['CustomHeading']))
        
        # Hash analysis
        if 'hashes' in static_results:
            story.append(Paragraph("Cryptographic Hashes", self.styles['CustomSubHeading']))
            hashes = static_results['hashes']
            
            hash_data = [
                ['Algorithm', 'Hash Value'],
                ['MD5', hashes.get('md5', 'N/A')],
                ['SHA1', hashes.get('sha1', 'N/A')],
                ['SHA256', hashes.get('sha256', 'N/A')]
            ]
            
            hash_table = Table(hash_data, colWidths=[1.5*inch, 4.5*inch])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#4472c4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, black)
            ]))
            
            story.append(hash_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Entropy analysis
        if 'entropy' in static_results:
            story.append(Paragraph("Entropy Analysis", self.styles['CustomSubHeading']))
            entropy = static_results['entropy']
            
            entropy_text = f"File entropy: <b>{entropy:.3f}</b><br/>"
            if entropy > 7:
                entropy_text += "<font color='red'>⚠️ Very high entropy - possible encryption/compression/packing</font>"
            elif entropy > 6:
                entropy_text += "<font color='orange'>⚠️ High entropy - potentially suspicious</font>"
            else:
                entropy_text += "<font color='green'>✅ Normal entropy levels</font>"
            
            story.append(Paragraph(entropy_text, self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # String analysis summary
        if 'strings' in static_results:
            story.append(Paragraph("String Analysis", self.styles['CustomSubHeading']))
            strings = static_results['strings']
            
            string_summary = f"""
            Total strings extracted: <b>{len(strings)}</b><br/>
            Average string length: <b>{sum(len(s) for s in strings) / len(strings) if strings else 0:.1f}</b><br/>
            Maximum string length: <b>{max(len(s) for s in strings) if strings else 0}</b>
            """
            
            story.append(Paragraph(string_summary, self.styles['Normal']))
            
            # Show sample strings
            if strings:
                story.append(Paragraph("Sample Strings (first 10):", self.styles['Normal']))
                for i, string in enumerate(strings[:10]):
                    story.append(Paragraph(f"{i+1}. {string[:80]}{'...' if len(string) > 80 else ''}", self.styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Pattern detection
        if 'patterns' in static_results:
            story.append(Paragraph("Pattern Detection", self.styles['CustomSubHeading']))
            patterns = static_results['patterns']
            
            pattern_summary = f"""
            URLs found: <b>{len(patterns.get('urls', []))}</b><br/>
            IP addresses found: <b>{len(patterns.get('ips', []))}</b><br/>
            Email addresses found: <b>{len(patterns.get('emails', []))}</b>
            """
            
            story.append(Paragraph(pattern_summary, self.styles['Normal']))
            
            # Show patterns if found
            for pattern_type, pattern_list in patterns.items():
                if pattern_list:
                    story.append(Paragraph(f"{pattern_type.title()}:", self.styles['Normal']))
                    for pattern in pattern_list[:5]:  # Show first 5
                        story.append(Paragraph(f"• {pattern}", self.styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
    
    def _add_virustotal_analysis(self, story, vt_results):
        """Add VirusTotal analysis results section"""
        story.append(Paragraph("VirusTotal Analysis Results", self.styles['CustomHeading']))
        
        if 'data' not in vt_results:
            story.append(Paragraph("No VirusTotal data available", self.styles['Normal']))
            return
        
        data = vt_results['data']['attributes']
        
        # Detection statistics
        stats = data.get('last_analysis_stats', {})
        if stats:
            story.append(Paragraph("Detection Statistics", self.styles['CustomSubHeading']))
            
            stats_data = [
                ['Category', 'Count'],
                ['Malicious', str(stats.get('malicious', 0))],
                ['Suspicious', str(stats.get('suspicious', 0))],
                ['Clean', str(stats.get('harmless', 0))],
                ['Undetected', str(stats.get('undetected', 0))]
            ]
            
            stats_table = Table(stats_data, colWidths=[2*inch, 1*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#4472c4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, black)
            ]))
            
            story.append(stats_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Engine results summary
        results = data.get('last_analysis_results', {})
        if results:
            story.append(Paragraph("Detection Engines Summary", self.styles['CustomSubHeading']))
            
            malicious_engines = []
            suspicious_engines = []
            
            for engine, result in results.items():
                category = result.get('category', 'undetected')
                if category == 'malicious':
                    malicious_engines.append(f"{engine}: {result.get('result', 'Detected')}")
                elif category == 'suspicious':
                    suspicious_engines.append(f"{engine}: {result.get('result', 'Suspicious')}")
            
            if malicious_engines:
                story.append(Paragraph("Engines detecting as malicious:", self.styles['Normal']))
                for engine in malicious_engines[:10]:  # Show first 10
                    story.append(Paragraph(f"• {engine}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            if suspicious_engines:
                story.append(Paragraph("Engines flagging as suspicious:", self.styles['Normal']))
                for engine in suspicious_engines[:10]:  # Show first 10
                    story.append(Paragraph(f"• {engine}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.3*inch))
    
    def _add_threat_assessment(self, story, report_data):
        """Add threat assessment section"""
        story.append(Paragraph("Threat Assessment", self.styles['CustomHeading']))
        
        threat_level = self._calculate_overall_threat_level(report_data)
        
        # Risk factors
        risk_factors = self._identify_risk_factors(report_data)
        
        if risk_factors:
            story.append(Paragraph("Identified Risk Factors:", self.styles['Normal']))
            for factor in risk_factors:
                story.append(Paragraph(f"• {factor}", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Overall assessment
        assessment_text = self._generate_threat_assessment_text(threat_level, risk_factors)
        
        if threat_level == "High":
            story.append(Paragraph(assessment_text, self.styles['Warning']))
        elif threat_level == "Medium":
            story.append(Paragraph(assessment_text, self.styles['Normal']))
        else:
            story.append(Paragraph(assessment_text, self.styles['Success']))
        
        story.append(Spacer(1, 0.3*inch))
    
    def _add_recommendations(self, story, report_data):
        """Add recommendations section"""
        story.append(Paragraph("Recommendations", self.styles['CustomHeading']))
        
        threat_level = self._calculate_overall_threat_level(report_data)
        recommendations = self._generate_recommendations(threat_level, report_data)
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Footer
        footer_text = """
        <para align=center>
        <b>Generated by MalwareShield Pro</b><br/>
        Professional Malware Analysis Platform<br/>
        For technical support or questions, contact your security team.
        </para>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))
    
    def _calculate_overall_threat_level(self, report_data):
        """Calculate overall threat level from all available data"""
        scores = []
        
        # Static analysis score
        if report_data.get('static_results') and 'threat_score' in report_data['static_results']:
            static_score = report_data['static_results']['threat_score'].get('score', 0)
            scores.append(static_score)
        
        # VirusTotal score
        if report_data.get('vt_results') and 'threat_score' in report_data['vt_results']:
            vt_score = report_data['vt_results']['threat_score'].get('score', 0)
            scores.append(vt_score)
        
        if not scores:
            return "Unknown"
        
        max_score = max(scores)
        
        if max_score >= 70:
            return "High"
        elif max_score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _get_threat_color(self, threat_level):
        """Get color code for threat level"""
        colors = {
            "High": "#ff0000",
            "Medium": "#ff8800",
            "Low": "#00aa00",
            "Unknown": "#888888"
        }
        return colors.get(threat_level, "#888888")
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    def _generate_executive_summary_text(self, report_data, threat_level):
        """Generate executive summary text"""
        file_name = "the uploaded file"
        if report_data.get('file_info'):
            file_name = report_data['file_info']['name']
        
        summary = f"This report presents the comprehensive malware analysis results for {file_name}. "
        
        if threat_level == "High":
            summary += "The analysis indicates a HIGH RISK threat level. Immediate action is recommended."
        elif threat_level == "Medium":
            summary += "The analysis indicates a MEDIUM RISK threat level. Caution is advised."
        elif threat_level == "Low":
            summary += "The analysis indicates a LOW RISK threat level. The file appears to be relatively safe."
        else:
            summary += "The threat level could not be determined from the available analysis data."
        
        # Add analysis method summary
        methods = []
        if report_data.get('static_results'):
            methods.append("static analysis")
        if report_data.get('vt_results'):
            methods.append("VirusTotal multi-engine scanning")
        
        if methods:
            summary += f" This assessment is based on {' and '.join(methods)}."
        
        return summary
    
    def _identify_risk_factors(self, report_data):
        """Identify specific risk factors from analysis results"""
        factors = []
        
        # Static analysis risk factors
        if report_data.get('static_results'):
            static = report_data['static_results']
            
            if 'entropy' in static and static['entropy'] > 7:
                factors.append("Very high file entropy (possible encryption/packing)")
            
            if 'patterns' in static:
                patterns = static['patterns']
                if patterns.get('urls'):
                    factors.append(f"Contains {len(patterns['urls'])} URL(s)")
                if patterns.get('ips'):
                    factors.append(f"Contains {len(patterns['ips'])} IP address(es)")
        
        # VirusTotal risk factors
        if report_data.get('vt_results'):
            vt_data = report_data['vt_results'].get('data', {}).get('attributes', {})
            stats = vt_data.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0:
                factors.append(f"Detected as malicious by {malicious} antivirus engine(s)")
            if suspicious > 0:
                factors.append(f"Flagged as suspicious by {suspicious} antivirus engine(s)")
        
        return factors
    
    def _generate_threat_assessment_text(self, threat_level, risk_factors):
        """Generate threat assessment text"""
        if threat_level == "High":
            text = "🚨 HIGH THREAT DETECTED: This file poses a significant security risk. "
            text += "Do not execute or open this file. Quarantine immediately and perform full system scan."
        elif threat_level == "Medium":
            text = "⚠️ MEDIUM THREAT DETECTED: This file shows suspicious characteristics. "
            text += "Exercise extreme caution. Recommend additional analysis before use."
        elif threat_level == "Low":
            text = "✅ LOW THREAT: This file appears to be relatively safe based on current analysis. "
            text += "However, maintain standard security practices."
        else:
            text = "❓ UNKNOWN THREAT LEVEL: Insufficient data to determine threat level. "
            text += "Recommend additional analysis."
        
        return text
    
    def _generate_recommendations(self, threat_level, report_data):
        """Generate security recommendations"""
        recommendations = []
        
        if threat_level == "High":
            recommendations.extend([
                "Immediately quarantine the file",
                "Do not execute or open the file under any circumstances",
                "Perform full system antivirus scan",
                "Check for signs of compromise on the system",
                "Report to security team immediately"
            ])
        elif threat_level == "Medium":
            recommendations.extend([
                "Exercise extreme caution with this file",
                "Perform additional analysis in isolated environment",
                "Do not execute on production systems",
                "Consider consulting security team",
                "Monitor system if file was previously executed"
            ])
        elif threat_level == "Low":
            recommendations.extend([
                "Maintain standard security practices",
                "Keep antivirus definitions updated",
                "Monitor file behavior if executed",
                "Regular system security scans"
            ])
        else:
            recommendations.extend([
                "Perform additional analysis to determine threat level",
                "Exercise caution until threat level is determined",
                "Consider multiple analysis engines",
                "Consult security team if uncertain"
            ])
        
        # Add general recommendations
        recommendations.extend([
            "Keep all security software updated",
            "Maintain regular system backups",
            "Educate users about file safety practices"
        ])
        
        return recommendations
