"""
MalwareShield Pro - Utility Modules
Advanced malware detection and analysis utilities
"""

__version__ = "1.0.0"
__author__ = "vishux777"
__all__ = ["VirusTotalAPI", "AnalysisEngine", "ReportGenerator", "ThreatScorer"]

# Import all utility classes for easy access
try:
    from .virustotal import VirusTotalAPI
except ImportError:
    pass

try:
    from .analysis_engine import AnalysisEngine
except ImportError:
    pass

try:
    from .report_generator import ReportGenerator
except ImportError:
    pass

try:
    from .threat_scorer import ThreatScorer
except ImportError:
    pass
