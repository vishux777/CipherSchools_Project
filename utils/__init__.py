"""
MalwareShield Pro Utilities Package

This package contains utility modules for malware analysis, VirusTotal integration,
threat scoring, and report generation.
"""

__version__ = "1.0.0"
__author__ = "MalwareShield Pro Team"

# Import main utility classes for easy access
try:
    from .virustotal import VirusTotalAPI
    from .analysis_engine import AnalysisEngine
    from .report_generator import ReportGenerator
    from .threat_scorer import ThreatScorer
except ImportError as e:
    import warnings
    warnings.warn(f"Some utility modules could not be imported: {e}")

__all__ = [
    'VirusTotalAPI',
    'AnalysisEngine', 
    'ReportGenerator',
    'ThreatScorer'
]
