import io
from datetime import datetime
from typing import Dict, Any, Optional
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus.flowables import HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
except ImportError:
    pass

class PDFGenerator:
    """PDF report generator for malware analysis results"""
    
    def __init__(self):
        try:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
        except:
            self.styles = None
    
    def _setup_custom_styles(self):
        """Setup custom styles for the PDF"""
        if not self.styles:
            return
            
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1e293b'),
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#475569'),
            borderWidth=1,
            borderColor=HexColor('#e2e8f0'),
            borderPadding=8
        ))
    
    def generate_report(self, report_data: Dict[Any, Any]) -> Optional[io.BytesIO]:
        """Generate comprehensive PDF report"""
        if not self.styles:
            return None
            
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=inch, leftMargin=inch,
                                  topMargin=inch, bottomMargin=inch)
            
            story = []
            
            # Add title page
            self._add_title_page(story, report_data)
            
            # Add file information
            if report_data.get('file_info'):
                self._add_file_information(story, report_data['file_info'])
            
            # Add static analysis results
            if report_data.get('static_results') and report_data.get('options', {}).get('include_static'):
                self._add_static_analysis(story, report_data['static_results'])
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            return buffer
            
        except Exception as e:
            print(f"Error generating PDF: {e}")
            return None
    
    def _add_title_page(self, story, report_data):
        """Add title page to the report"""
        story.append(Spacer(1, 2*inch))
        
        title = Paragraph("MalwareShield Pro", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        subtitle = Paragraph("Comprehensive Malware Analysis Report", self.styles['CustomHeading'])
        story.append(subtitle)
        
        story.append(PageBreak())
    
    def _add_file_information(self, story, file_info):
        """Add file information section"""
        story.append(Paragraph("File Information", self.styles['CustomHeading']))
        story.append(Spacer(1, 12))
        
        file_data = [
            ['File Name', file_info.get('name', 'Unknown')],
            ['File Size', self._format_file_size(file_info.get('size', 0))],
            ['File Type', file_info.get('type', 'Unknown')],
        ]
        
        file_table = Table(file_data, colWidths=[2*inch, 4*inch])
        file_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8fafc')),
        ]))
        story.append(file_table)
        story.append(Spacer(1, 20))
    
    def _add_static_analysis(self, story, static_results):
        """Add static analysis results section"""
        story.append(Paragraph("Static Analysis Results", self.styles['CustomHeading']))
        story.append(Spacer(1, 12))
        
        if 'hashes' in static_results:
            hashes = static_results['hashes']
            hash_data = [
                ['MD5', hashes.get('md5', 'N/A')],
                ['SHA1', hashes.get('sha1', 'N/A')],
                ['SHA256', hashes.get('sha256', 'N/A')]
            ]
            
            hash_table = Table(hash_data, colWidths=[1*inch, 4*inch])
            hash_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ]))
            story.append(hash_table)
        
        story.append(Spacer(1, 20))
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"