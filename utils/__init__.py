"""
MalwareShield Pro Utility Modules

This package contains utility modules for malware analysis including:
- VirusTotal API integration
- Analysis engine for file processing
- Report generation and export
- Threat scoring and assessment
"""

__version__ = "1.0.0"
__author__ = "MalwareShield Pro Team"

# Import main classes for easy access
try:
    from .virustotal import VirusTotalAPI
except ImportError:
    VirusTotalAPI = None

try:
    from .analysis_engine import AnalysisEngine
except ImportError:
    AnalysisEngine = None

try:
    from .report_generator import ReportGenerator
except ImportError:
    ReportGenerator = None

try:
    from .threat_scorer import ThreatScorer
except ImportError:
    ThreatScorer = None

__all__ = [
    'VirusTotalAPI',
    'AnalysisEngine', 
    'ReportGenerator',
    'ThreatScorer'
]
