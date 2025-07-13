"""
Threat Scorer Module

Provides intelligent threat scoring and risk assessment capabilities based on
comprehensive analysis of file characteristics, patterns, and external intelligence.
"""

from typing import Dict, List, Any, Tuple
import re
import math

class ThreatScorer:
    """Advanced threat scoring engine for malware risk assessment"""
    
    def __init__(self):
        """Initialize the threat scorer"""
        self.scoring_weights = self._initialize_weights()
        self.threat_thresholds = {
            'CLEAN': (0, 20),
            'LOW': (21, 40), 
            'MEDIUM': (41, 65),
            'HIGH': (66, 85),
            'CRITICAL': (86, 100)
        }
    
    def calculate_score(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive threat score
        
        Args:
            analysis_data: Complete analysis results
            
        Returns:
            dict: Threat assessment with score, level, and reasoning
        """
        try:
            # Initialize scoring components
            scores = {
                'entropy': 0,
                'file_size': 0,
                'patterns': 0,
                'strings': 0,
                'virustotal': 0,
                'signatures': 0,
                'file_type': 0,
                'metadata': 0
            }
            
            reasons = []
            
            # Calculate individual component scores
            scores['entropy'], entropy_reasons = self._score_entropy(analysis_data)
            scores['file_size'], size_reasons = self._score_file_size(analysis_data)
            scores['patterns'], pattern_reasons = self._score_patterns(analysis_data)
            scores['strings'], string_reasons = self._score_strings(analysis_data)
            scores['virustotal'], vt_reasons = self._score_virustotal(analysis_data)
            scores['signatures'], sig_reasons = self._score_signatures(analysis_data)
            scores['file_type'], type_reasons = self._score_file_type(analysis_data)
            scores['metadata'], meta_reasons = self._score_metadata(analysis_data)
            
            # Combine all reasons
            reasons.extend(entropy_reasons)
            reasons.extend(size_reasons)
            reasons.extend(pattern_reasons)
            reasons.extend(string_reasons)
            reasons.extend(vt_reasons)
            reasons.extend(sig_reasons)
            reasons.extend(type_reasons)
            reasons.extend(meta_reasons)
            
            # Calculate weighted total score
            total_score = self._calculate_weighted_score(scores)
            
            # Determine threat level
            threat_level = self._determine_threat_level(total_score)
            
            # Apply threat level modifiers
            total_score, threat_level = self._apply_modifiers(total_score, threat_level, analysis_data)
            
            return {
                'score': min(100, max(0, int(total_score))),
                'level': threat_level,
                'reasons': reasons[:15],  # Limit to top 15 reasons
                'component_scores': scores,
                'raw_score': total_score
            }
            
        except Exception as e:
            return {
                'score': 0,
                'level': 'ERROR',
                'reasons': [f'Scoring failed: {str(e)}'],
                'component_scores': {},
                'raw_score': 0
            }
    
    def _initialize_weights(self) -> Dict[str, float]:
        """Initialize scoring weights for different components"""
        return {
            'entropy': 0.15,      # File entropy analysis
            'file_size': 0.05,    # File size characteristics
            'patterns': 0.25,     # Suspicious patterns detected
            'strings': 0.10,      # String analysis results
            'virustotal': 0.30,   # VirusTotal detection results
            'signatures': 0.10,   # Known malware signatures
            'file_type': 0.03,    # File type risk assessment
            'metadata': 0.02      # File metadata analysis
        }
    
    def _score_entropy(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on file entropy
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        entropy = analysis_data.get('entropy', 0)
        reasons = []
        
        if entropy >= 7.8:
            score = 80
            reasons.append(f"Very high entropy ({entropy:.2f}) - likely packed or encrypted")
        elif entropy >= 7.5:
            score = 60
            reasons.append(f"High entropy ({entropy:.2f}) - possible packing detected")
        elif entropy >= 6.5:
            score = 30
            reasons.append(f"Moderate entropy ({entropy:.2f}) - some compression/encoding")
        elif entropy <= 1.0:
            score = 5
            reasons.append(f"Very low entropy ({entropy:.2f}) - unusual for executable files")
        else:
            score = 0
            reasons.append(f"Normal entropy ({entropy:.2f})")
        
        return score, reasons
    
    def _score_file_size(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on file size characteristics
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        file_size = analysis_data.get('file_size', 0)
        reasons = []
        
        if file_size < 1024:  # Less than 1KB
            score = 25
            reasons.append(f"Suspiciously small file size ({file_size} bytes)")
        elif file_size > 100 * 1024 * 1024:  # Greater than 100MB
            score = 15
            reasons.append(f"Unusually large file size ({self._format_size(file_size)})")
        elif file_size < 10 * 1024:  # Less than 10KB
            score = 10
            reasons.append(f"Small file size ({self._format_size(file_size)}) - typical for droppers")
        else:
            score = 0
        
        return score, reasons
    
    def _score_patterns(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on detected suspicious patterns
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        patterns = analysis_data.get('patterns', {})
        score = 0
        reasons = []
        
        pattern_weights = {
            'crypto': 40,           # Cryptocurrency indicators
            'network': 30,          # Network-related patterns
            'system': 25,           # System manipulation
            'malware': 50,          # Known malware indicators
            'persistence': 35,      # Persistence mechanisms
            'steganography': 45,    # Steganography indicators
            'suspicious_apis': 30,  # Suspicious API calls
            'registry_keys': 20,    # Registry manipulation
            'file_paths': 15,       # Suspicious file paths
            'urls': 25,            # URLs in binary
            'ips': 30,             # IP addresses
            'emails': 10,          # Email addresses
            'bitcoin_addresses': 45, # Bitcoin addresses
            'ethereum_addresses': 45 # Ethereum addresses
        }
        
        for pattern_type, matches in patterns.items():
            if matches:
                pattern_score = pattern_weights.get(pattern_type, 10)
                match_count = len(matches)
                
                # Scale score based on number of matches
                if match_count > 10:
                    multiplier = 2.0
                elif match_count > 5:
                    multiplier = 1.5
                else:
                    multiplier = 1.0
                
                component_score = min(pattern_score * multiplier, 70)
                score += component_score
                
                reasons.append(f"{pattern_type.replace('_', ' ').title()}: {match_count} matches (+{component_score:.0f} points)")
        
        return min(score, 100), reasons
    
    def _score_strings(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on string analysis
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        strings = analysis_data.get('strings', [])
        score = 0
        reasons = []
        
        if not strings:
            score = 20
            reasons.append("No readable strings found - possible obfuscation")
            return score, reasons
        
        string_count = len(strings)
        
        # Analyze string characteristics
        suspicious_keywords = [
            'password', 'keylog', 'backdoor', 'trojan', 'virus',
            'malware', 'decrypt', 'encrypt', 'ransom', 'bitcoin',
            'payload', 'shellcode', 'exploit', 'injection', 'rootkit'
        ]
        
        suspicious_count = 0
        for string_val in strings:
            string_lower = string_val.lower()
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    suspicious_count += 1
                    break
        
        if suspicious_count > 0:
            score = min(suspicious_count * 15, 60)
            reasons.append(f"{suspicious_count} suspicious keywords found in strings")
        
        # Check for very few strings (possible packing)
        if string_count < 10:
            score += 15
            reasons.append(f"Very few strings extracted ({string_count}) - possible packing")
        elif string_count < 50:
            score += 5
            reasons.append(f"Few strings extracted ({string_count}) - minimal text content")
        
        return min(score, 80), reasons
    
    def _score_virustotal(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on VirusTotal results
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        vt_data = analysis_data.get('virustotal', {})
        
        if 'error' in vt_data or not vt_data:
            return 0, ["No VirusTotal data available"]
        
        stats = vt_data.get('stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = stats.get('total', 0)
        
        if total == 0:
            return 0, ["No VirusTotal engines reported"]
        
        # Calculate detection percentage
        detection_percentage = ((malicious + suspicious) / total) * 100
        
        reasons = []
        
        if malicious > 20:
            score = 95
            reasons.append(f"High malware detection: {malicious}/{total} engines ({detection_percentage:.1f}%)")
        elif malicious > 10:
            score = 85
            reasons.append(f"Significant malware detection: {malicious}/{total} engines ({detection_percentage:.1f}%)")
        elif malicious > 5:
            score = 70
            reasons.append(f"Multiple engines detected threats: {malicious}/{total} engines ({detection_percentage:.1f}%)")
        elif malicious > 2:
            score = 50
            reasons.append(f"Several engines detected threats: {malicious}/{total} engines ({detection_percentage:.1f}%)")
        elif malicious > 0:
            score = 35
            reasons.append(f"Some engines detected threats: {malicious}/{total} engines ({detection_percentage:.1f}%)")
        elif suspicious > 5:
            score = 25
            reasons.append(f"Multiple engines flagged as suspicious: {suspicious}/{total} engines")
        elif suspicious > 0:
            score = 10
            reasons.append(f"Some engines flagged as suspicious: {suspicious}/{total} engines")
        else:
            score = 0
            reasons.append(f"Clean VirusTotal scan: 0/{total} detections")
        
        return score, reasons
    
    def _score_signatures(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on malware signature matches
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        # This would be populated by the analysis engine
        signatures = analysis_data.get('signatures', {})
        matches = signatures.get('matches', [])
        
        if not matches:
            return 0, []
        
        score = 0
        reasons = []
        
        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30
        }
        
        for match in matches:
            severity = match.get('severity', 'medium')
            match_score = severity_scores.get(severity, 50)
            score = max(score, match_score)  # Take highest severity
            
            reasons.append(f"Malware signature detected: {match.get('name', 'Unknown')} (Severity: {severity})")
        
        return min(score, 100), reasons
    
    def _score_file_type(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on file type risk assessment
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        file_type = analysis_data.get('file_type', '').lower()
        reasons = []
        
        high_risk_types = ['exe', 'dll', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js']
        medium_risk_types = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
        executable_types = ['application/x-executable', 'application/x-msdos-program']
        
        if any(risk_type in file_type for risk_type in executable_types):
            score = 20
            reasons.append(f"Executable file type detected: {file_type}")
        elif any(risk_type in file_type for risk_type in high_risk_types):
            score = 15
            reasons.append(f"High-risk file type: {file_type}")
        elif any(risk_type in file_type for risk_type in medium_risk_types):
            score = 10
            reasons.append(f"Medium-risk file type: {file_type}")
        else:
            score = 0
        
        return score, reasons
    
    def _score_metadata(self, analysis_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on file metadata analysis
        
        Args:
            analysis_data: Analysis results
            
        Returns:
            tuple: (score, reasons)
        """
        # Placeholder for metadata analysis
        # Could include PE headers, digital signatures, etc.
        return 0, []
    
    def _calculate_weighted_score(self, scores: Dict[str, float]) -> float:
        """Calculate weighted total score
        
        Args:
            scores: Individual component scores
            
        Returns:
            float: Weighted total score
        """
        total_score = 0
        
        for component, score in scores.items():
            weight = self.scoring_weights.get(component, 0)
            total_score += score * weight
        
        return total_score
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level based on score
        
        Args:
            score: Calculated threat score
            
        Returns:
            str: Threat level
        """
        for level, (min_score, max_score) in self.threat_thresholds.items():
            if min_score <= score <= max_score:
                return level
        
        return 'UNKNOWN'
    
    def _apply_modifiers(self, score: float, threat_level: str, analysis_data: Dict[str, Any]) -> Tuple[float, str]:
        """Apply final modifiers to score and threat level
        
        Args:
            score: Current score
            threat_level: Current threat level
            analysis_data: Analysis results
            
        Returns:
            tuple: (modified_score, modified_threat_level)
        """
        # Boost score for multiple concerning factors
        concerning_factors = 0
        
        # High entropy + suspicious patterns
        if analysis_data.get('entropy', 0) > 7.5 and analysis_data.get('patterns', {}):
            concerning_factors += 1
        
        # VirusTotal detections + local analysis flags
        vt_data = analysis_data.get('virustotal', {})
        if vt_data.get('stats', {}).get('malicious', 0) > 0 and analysis_data.get('patterns', {}):
            concerning_factors += 1
        
        # Signature matches + other indicators
        signatures = analysis_data.get('signatures', {})
        if signatures.get('matches', []) and analysis_data.get('patterns', {}):
            concerning_factors += 1
        
        # Apply modifiers
        if concerning_factors >= 2:
            score = min(score * 1.2, 100)  # 20% boost
            # Potentially upgrade threat level
            if threat_level == 'MEDIUM' and score > 70:
                threat_level = 'HIGH'
            elif threat_level == 'HIGH' and score > 90:
                threat_level = 'CRITICAL'
        
        return score, threat_level
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
