"""
Threat Scoring Engine for MalwareShield Pro
Calculates threat levels based on analysis results

Built with 🛡️ by [Vishwas]
"""

from typing import Dict, List, Any, Tuple
import math

class ThreatScorer:
    """Advanced threat scoring engine"""
    
    def __init__(self):
        self.threat_levels = {
            'CLEAN': (0, 20),
            'LOW': (21, 40),
            'MEDIUM': (41, 60),
            'HIGH': (61, 80),
            'CRITICAL': (81, 100)
        }
        
        self.scoring_weights = {
            'entropy': 0.25,
            'suspicious_patterns': 0.20,
            'suspicious_indicators': 0.20,
            'file_characteristics': 0.15,
            'virustotal_detection': 0.20
        }
    
    def calculate_score(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive threat score
        
        Args:
            analysis_data: Complete analysis results
            
        Returns:
            Dict containing threat score, level, and reasoning
        """
        try:
            scores = {}
            reasons = []
            
            # Entropy scoring
            entropy_score, entropy_reasons = self._score_entropy(analysis_data)
            scores['entropy'] = entropy_score
            reasons.extend(entropy_reasons)
            
            # Pattern scoring
            pattern_score, pattern_reasons = self._score_patterns(analysis_data)
            scores['suspicious_patterns'] = pattern_score
            reasons.extend(pattern_reasons)
            
            # Indicator scoring
            indicator_score, indicator_reasons = self._score_indicators(analysis_data)
            scores['suspicious_indicators'] = indicator_score
            reasons.extend(indicator_reasons)
            
            # File characteristics scoring
            file_score, file_reasons = self._score_file_characteristics(analysis_data)
            scores['file_characteristics'] = file_score
            reasons.extend(file_reasons)
            
            # VirusTotal scoring
            vt_score, vt_reasons = self._score_virustotal(analysis_data)
            scores['virustotal_detection'] = vt_score
            reasons.extend(vt_reasons)
            
            # Calculate weighted final score
            final_score = 0
            for category, score in scores.items():
                weight = self.scoring_weights.get(category, 0)
                final_score += score * weight
            
            final_score = min(100, max(0, int(final_score)))
            
            # Determine threat level
            threat_level = self._determine_threat_level(final_score)
            
            return {
                'score': final_score,
                'level': threat_level,
                'scores': scores,
                'reasons': reasons[:10],  # Limit to top 10 reasons
                'confidence': self._calculate_confidence(scores)
            }
            
        except Exception as e:
            return {
                'score': 0,
                'level': 'UNKNOWN',
                'error': f"Threat scoring failed: {str(e)}",
                'reasons': ['Unable to calculate threat score']
            }
    
    def _score_entropy(self, data: Dict) -> Tuple[float, List[str]]:
        """Score based on file entropy"""
        entropy = data.get('entropy', 0)
        reasons = []
        
        if entropy > 7.5:
            reasons.append("Extremely high entropy - likely packed/encrypted")
            return 90, reasons
        elif entropy > 7.0:
            reasons.append("Very high entropy - possibly packed")
            return 75, reasons
        elif entropy > 6.5:
            reasons.append("High entropy - suspicious compression")
            return 60, reasons
        elif entropy > 6.0:
            reasons.append("Moderately high entropy")
            return 40, reasons
        elif entropy > 5.0:
            reasons.append("Normal entropy levels")
            return 20, reasons
        else:
            reasons.append("Low entropy - normal file structure")
            return 5, reasons
    
    def _score_patterns(self, data: Dict) -> Tuple[float, List[str]]:
        """Score based on suspicious patterns"""
        patterns = data.get('patterns', {})
        score = 0
        reasons = []
        
        # URLs
        urls = patterns.get('urls', [])
        if urls:
            url_score = min(50, len(urls) * 10)
            score += url_score
            reasons.append(f"Contains {len(urls)} URLs")
        
        # IP addresses
        ips = patterns.get('ips', [])
        if ips:
            ip_score = min(40, len(ips) * 15)
            score += ip_score
            reasons.append(f"Contains {len(ips)} IP addresses")
        
        # Suspicious keywords
        keywords = patterns.get('suspicious_keywords', [])
        if keywords:
            keyword_score = min(60, len(keywords) * 8)
            score += keyword_score
            reasons.append(f"Contains {len(keywords)} suspicious keywords")
        
        # Registry keys
        registry = patterns.get('registry_keys', [])
        if registry:
            reg_score = min(30, len(registry) * 12)
            score += reg_score
            reasons.append(f"Contains {len(registry)} registry modifications")
        
        # File paths
        paths = patterns.get('file_paths', [])
        if paths:
            path_score = min(25, len(paths) * 5)
            score += path_score
            reasons.append(f"Contains {len(paths)} file paths")
        
        return min(100, score), reasons
    
    def _score_indicators(self, data: Dict) -> Tuple[float, List[str]]:
        """Score based on suspicious indicators"""
        indicators = data.get('suspicious_indicators', [])
        score = 0
        reasons = []
        
        if not indicators:
            return 0, reasons
        
        # Each indicator adds to the score
        for indicator in indicators:
            if 'high entropy' in indicator.lower():
                score += 25
            elif 'api call' in indicator.lower():
                score += 20
            elif 'network' in indicator.lower():
                score += 15
            elif 'crypto' in indicator.lower():
                score += 10
            elif 'persistence' in indicator.lower():
                score += 15
            else:
                score += 5
        
        if indicators:
            reasons.append(f"Multiple suspicious indicators detected ({len(indicators)})")
        
        return min(100, score), reasons
    
    def _score_file_characteristics(self, data: Dict) -> Tuple[float, List[str]]:
        """Score based on file characteristics"""
        score = 0
        reasons = []
        
        # File size analysis
        file_size = data.get('file_size', 0)
        if file_size > 50 * 1024 * 1024:  # > 50MB
            score += 15
            reasons.append("Unusually large file size")
        elif file_size < 100:  # < 100 bytes
            score += 25
            reasons.append("Suspiciously small file size")
        
        # File type analysis
        file_type = data.get('file_type', '')
        if file_type == 'Unknown':
            score += 20
            reasons.append("Unknown file type")
        elif 'executable' in file_type.lower():
            score += 10
            reasons.append("Executable file type")
        
        # String analysis
        strings = data.get('strings', [])
        if len(strings) > 10000:
            score += 15
            reasons.append("Excessive number of strings")
        elif len(strings) < 10:
            score += 20
            reasons.append("Very few readable strings")
        
        return min(100, score), reasons
    
    def _score_virustotal(self, data: Dict) -> Tuple[float, List[str]]:
        """Score based on VirusTotal results"""
        vt_results = data.get('virustotal_results')
        reasons = []
        
        if not vt_results or 'error' in vt_results:
            return 0, reasons
        
        positive_scans = vt_results.get('positive_scans', 0)
        total_scans = vt_results.get('total_scans', 0)
        
        if total_scans == 0:
            return 0, reasons
        
        detection_ratio = positive_scans / total_scans
        
        if detection_ratio >= 0.5:
            score = 100
            reasons.append(f"High VirusTotal detection: {positive_scans}/{total_scans}")
        elif detection_ratio >= 0.3:
            score = 80
            reasons.append(f"Moderate VirusTotal detection: {positive_scans}/{total_scans}")
        elif detection_ratio >= 0.1:
            score = 60
            reasons.append(f"Low VirusTotal detection: {positive_scans}/{total_scans}")
        elif detection_ratio > 0:
            score = 40
            reasons.append(f"Minimal VirusTotal detection: {positive_scans}/{total_scans}")
        else:
            score = 0
            reasons.append("Clean VirusTotal scan")
        
        return score, reasons
    
    def _determine_threat_level(self, score: int) -> str:
        """Determine threat level based on score"""
        for level, (min_score, max_score) in self.threat_levels.items():
            if min_score <= score <= max_score:
                return level
        return 'UNKNOWN'
    
    def _calculate_confidence(self, scores: Dict) -> float:
        """Calculate confidence level of the assessment"""
        # Confidence based on data availability and consistency
        available_metrics = sum(1 for score in scores.values() if score > 0)
        total_metrics = len(scores)
        
        if total_metrics == 0:
            return 0.0
        
        base_confidence = available_metrics / total_metrics
        
        # Adjust confidence based on score consistency
        score_values = [score for score in scores.values() if score > 0]
        if len(score_values) > 1:
            score_variance = sum((score - sum(score_values)/len(score_values))**2 for score in score_values) / len(score_values)
            consistency_factor = max(0.5, 1 - (score_variance / 2500))  # Normalize variance
            base_confidence *= consistency_factor
        
        return round(base_confidence, 2)
    
    def get_threat_description(self, threat_level: str) -> str:
        """Get description for threat level"""
        descriptions = {
            'CLEAN': "File appears to be clean with no significant threats detected.",
            'LOW': "File shows minimal suspicious characteristics. Low risk.",
            'MEDIUM': "File contains some suspicious patterns. Moderate risk.",
            'HIGH': "File shows multiple suspicious indicators. High risk.",
            'CRITICAL': "File is highly suspicious with severe threat indicators. Critical risk."
        }
        return descriptions.get(threat_level, "Unknown threat level")
