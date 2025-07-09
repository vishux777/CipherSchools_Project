import math
from typing import Dict, Any, List

class ThreatScorer:
    """Advanced threat scoring system for malware analysis results"""
    
    def __init__(self):
        # Weight factors for different analysis components
        self.weights = {
            'entropy': 0.25,
            'strings': 0.15,
            'patterns': 0.20,
            'file_size': 0.10,
            'file_type': 0.15,
            'suspicious_patterns': 0.15
        }
        
        # VirusTotal weight factors
        self.vt_weights = {
            'malicious_ratio': 0.60,
            'suspicious_ratio': 0.25,
            'reputation': 0.15
        }
    
    def calculate_static_threat_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat score from static analysis results"""
        scores = {}
        total_score = 0
        
        # Entropy scoring
        entropy_score = self._score_entropy(analysis_results.get('entropy', 0))
        scores['entropy'] = entropy_score
        total_score += entropy_score * self.weights['entropy']
        
        # String analysis scoring
        string_score = self._score_strings(analysis_results.get('strings', []))
        scores['strings'] = string_score
        total_score += string_score * self.weights['strings']
        
        # Pattern detection scoring
        pattern_score = self._score_patterns(analysis_results.get('patterns', {}))
        scores['patterns'] = pattern_score
        total_score += pattern_score * self.weights['patterns']
        
        # File metadata scoring
        metadata_score = self._score_metadata(analysis_results.get('metadata', {}))
        scores['metadata'] = metadata_score
        total_score += metadata_score * (self.weights['file_size'] + self.weights['file_type'])
        
        # Suspicious pattern scoring (if available)
        if 'suspicious_patterns' in analysis_results:
            suspicious_score = self._score_suspicious_patterns(analysis_results['suspicious_patterns'])
            scores['suspicious_patterns'] = suspicious_score
            total_score += suspicious_score * self.weights['suspicious_patterns']
        
        # Normalize to 0-100 scale
        final_score = min(100, max(0, total_score))
        
        return {
            'score': round(final_score, 1),
            'level': self._get_threat_level(final_score),
            'component_scores': scores,
            'risk_factors': self._identify_risk_factors(analysis_results, scores)
        }
    
    def calculate_virustotal_threat_score(self, vt_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat score from VirusTotal results"""
        if 'data' not in vt_results:
            return {'score': 0, 'level': 'Unknown', 'component_scores': {}}
        
        data = vt_results['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        
        scores = {}
        total_score = 0
        
        # Calculate detection ratios
        total_engines = sum(stats.values()) if stats else 0
        if total_engines > 0:
            malicious_ratio = stats.get('malicious', 0) / total_engines
            suspicious_ratio = stats.get('suspicious', 0) / total_engines
        else:
            malicious_ratio = 0
            suspicious_ratio = 0
        
        # Malicious detection scoring
        malicious_score = malicious_ratio * 100
        scores['malicious'] = malicious_score
        total_score += malicious_score * self.vt_weights['malicious_ratio']
        
        # Suspicious detection scoring
        suspicious_score = suspicious_ratio * 50  # Suspicious gets half weight
        scores['suspicious'] = suspicious_score
        total_score += suspicious_score * self.vt_weights['suspicious_ratio']
        
        # Reputation scoring (based on community votes, if available)
        reputation_score = self._score_vt_reputation(data)
        scores['reputation'] = reputation_score
        total_score += reputation_score * self.vt_weights['reputation']
        
        final_score = min(100, max(0, total_score))
        
        return {
            'score': round(final_score, 1),
            'level': self._get_threat_level(final_score),
            'component_scores': scores,
            'detection_stats': stats,
            'engine_details': self._analyze_engine_detections(data.get('last_analysis_results', {}))
        }
    
    def calculate_combined_threat_score(self, static_score: Dict[str, Any], vt_score: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate combined threat score from both static and VirusTotal analysis"""
        static_weight = 0.4
        vt_weight = 0.6
        
        static_val = static_score.get('score', 0)
        vt_val = vt_score.get('score', 0)
        
        # If only one score is available, use it with reduced confidence
        if static_val > 0 and vt_val > 0:
            combined_score = (static_val * static_weight) + (vt_val * vt_weight)
            confidence = 'High'
        elif vt_val > 0:
            combined_score = vt_val * 0.9  # Slightly reduce score if no static analysis
            confidence = 'Medium'
        elif static_val > 0:
            combined_score = static_val * 0.8  # Reduce score if no VT analysis
            confidence = 'Medium'
        else:
            combined_score = 0
            confidence = 'Low'
        
        return {
            'score': round(combined_score, 1),
            'level': self._get_threat_level(combined_score),
            'confidence': confidence,
            'static_contribution': round(static_val * static_weight, 1) if static_val > 0 else 0,
            'virustotal_contribution': round(vt_val * vt_weight, 1) if vt_val > 0 else 0
        }
    
    def _score_entropy(self, entropy: float) -> float:
        """Score file entropy (0-100)"""
        if entropy >= 7.5:
            return 90  # Very high entropy - likely packed/encrypted
        elif entropy >= 7.0:
            return 70  # High entropy - suspicious
        elif entropy >= 6.5:
            return 40  # Moderately high entropy
        elif entropy >= 6.0:
            return 20  # Slightly elevated entropy
        else:
            return 5   # Normal entropy
    
    def _score_strings(self, strings: List[str]) -> float:
        """Score string analysis results (0-100)"""
        if not strings:
            return 20  # No strings could indicate packing
        
        string_count = len(strings)
        avg_length = sum(len(s) for s in strings) / string_count
        
        score = 0
        
        # Score based on string count
        if string_count < 10:
            score += 30  # Very few strings - suspicious
        elif string_count < 50:
            score += 15  # Few strings - potentially suspicious
        else:
            score += 5   # Normal string count
        
        # Score based on average string length
        if avg_length > 100:
            score += 20  # Very long strings - potentially obfuscated
        elif avg_length > 50:
            score += 10  # Long strings
        
        # Check for suspicious string patterns
        suspicious_keywords = [
            'encrypt', 'decrypt', 'payload', 'shellcode', 'backdoor',
            'keylog', 'password', 'steal', 'inject', 'exploit'
        ]
        
        suspicious_count = 0
        for string in strings:
            if any(keyword in string.lower() for keyword in suspicious_keywords):
                suspicious_count += 1
        
        if suspicious_count > 5:
            score += 40
        elif suspicious_count > 2:
            score += 20
        elif suspicious_count > 0:
            score += 10
        
        return min(100, score)
    
    def _score_patterns(self, patterns: Dict[str, List[str]]) -> float:
        """Score pattern detection results (0-100)"""
        score = 0
        
        # URLs
        url_count = len(patterns.get('urls', []))
        if url_count > 10:
            score += 40
        elif url_count > 5:
            score += 25
        elif url_count > 0:
            score += 15
        
        # IP addresses
        ip_count = len(patterns.get('ips', []))
        if ip_count > 5:
            score += 30
        elif ip_count > 2:
            score += 20
        elif ip_count > 0:
            score += 10
        
        # Email addresses
        email_count = len(patterns.get('emails', []))
        if email_count > 3:
            score += 20
        elif email_count > 0:
            score += 10
        
        # File paths
        path_count = len(patterns.get('file_paths', []))
        if path_count > 10:
            score += 15
        elif path_count > 5:
            score += 10
        
        # Registry keys (Windows-specific)
        reg_count = len(patterns.get('registry_keys', []))
        if reg_count > 5:
            score += 25
        elif reg_count > 0:
            score += 15
        
        return min(100, score)
    
    def _score_metadata(self, metadata: Dict[str, Any]) -> float:
        """Score file metadata (0-100)"""
        score = 0
        
        # File size scoring
        file_size = metadata.get('size', 0)
        if file_size > 10 * 1024 * 1024:  # > 10MB
            score += 15  # Large files can hide malware
        elif file_size < 1024:  # < 1KB
            score += 25  # Very small files are suspicious
        
        # File type scoring
        file_sig = metadata.get('file_signature', {})
        if file_sig.get('primary_type') == 'pe_executable':
            score += 20  # Executables are higher risk
        elif file_sig.get('primary_type') in ['unknown', 'none']:
            score += 30  # Unknown file types are suspicious
        
        # PE-specific scoring
        pe_analysis = metadata.get('pe_analysis', {})
        if pe_analysis.get('is_pe'):
            if pe_analysis.get('sections', 0) < 3:
                score += 20  # Few sections might indicate packing
            elif pe_analysis.get('sections', 0) > 10:
                score += 15  # Many sections might indicate complexity
        
        # Null byte percentage
        null_percentage = metadata.get('null_percentage', 0)
        if null_percentage > 50:
            score += 20  # High null content is suspicious
        elif null_percentage < 1:
            score += 10  # Very low null content might indicate packing
        
        return min(100, score)
    
    def _score_suspicious_patterns(self, suspicious_patterns: Dict[str, List[str]]) -> float:
        """Score suspicious pattern analysis (0-100)"""
        score = 0
        
        # Obfuscation indicators
        obfuscation_count = len(suspicious_patterns.get('obfuscation_indicators', []))
        score += min(40, obfuscation_count * 15)
        
        # Encoding patterns
        encoding_count = len(suspicious_patterns.get('encoding_patterns', []))
        score += min(30, encoding_count * 20)
        
        # Suspicious APIs
        api_count = len(suspicious_patterns.get('suspicious_apis', []))
        score += min(50, api_count * 5)
        
        return min(100, score)
    
    def _score_vt_reputation(self, vt_data: Dict[str, Any]) -> float:
        """Score VirusTotal reputation data (0-100)"""
        score = 0
        
        # Check community votes
        votes = vt_data.get('total_votes', {})
        if votes:
            malicious_votes = votes.get('malicious', 0)
            harmless_votes = votes.get('harmless', 0)
            total_votes = malicious_votes + harmless_votes
            
            if total_votes > 0:
                malicious_ratio = malicious_votes / total_votes
                score = malicious_ratio * 100
        
        # Check reputation score if available
        reputation = vt_data.get('reputation', 0)
        if reputation < -50:
            score = max(score, 80)
        elif reputation < -10:
            score = max(score, 50)
        elif reputation > 50:
            score = min(score, 10)
        
        return score
    
    def _analyze_engine_detections(self, engine_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual engine detection patterns"""
        analysis = {
            'total_engines': len(engine_results),
            'detected_engines': [],
            'suspicious_engines': [],
            'detection_families': {},
            'confidence_indicators': []
        }
        
        for engine, result in engine_results.items():
            category = result.get('category', 'undetected')
            detection_result = result.get('result', '')
            
            if category == 'malicious':
                analysis['detected_engines'].append({
                    'engine': engine,
                    'result': detection_result,
                    'version': result.get('version', 'unknown')
                })
                
                # Extract malware family
                if detection_result and detection_result != 'Malware':
                    family = detection_result.split('.')[0] if '.' in detection_result else detection_result
                    analysis['detection_families'][family] = analysis['detection_families'].get(family, 0) + 1
            
            elif category == 'suspicious':
                analysis['suspicious_engines'].append({
                    'engine': engine,
                    'result': detection_result
                })
        
        # Calculate confidence indicators
        detection_count = len(analysis['detected_engines'])
        if detection_count > 10:
            analysis['confidence_indicators'].append('High confidence - multiple engines detected')
        elif detection_count > 5:
            analysis['confidence_indicators'].append('Medium confidence - several engines detected')
        elif detection_count > 0:
            analysis['confidence_indicators'].append('Low confidence - few engines detected')
        
        # Check for consensus on malware family
        if analysis['detection_families']:
            most_common_family = max(analysis['detection_families'], key=analysis['detection_families'].get)
            family_count = analysis['detection_families'][most_common_family]
            if family_count >= detection_count * 0.6:
                analysis['confidence_indicators'].append(f'Family consensus: {most_common_family}')
        
        return analysis
    
    def _get_threat_level(self, score: float) -> str:
        """Convert numerical score to threat level"""
        if score >= 70:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score > 0:
            return 'Low'
        else:
            return 'Unknown'
    
    def _identify_risk_factors(self, analysis_results: Dict[str, Any], scores: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors from analysis"""
        risk_factors = []
        
        # High entropy
        if scores.get('entropy', 0) > 60:
            risk_factors.append('High file entropy detected (possible packing/encryption)')
        
        # Suspicious strings
        if scores.get('strings', 0) > 50:
            risk_factors.append('Suspicious string patterns detected')
        
        # Network indicators
        patterns = analysis_results.get('patterns', {})
        if len(patterns.get('urls', [])) > 5:
            risk_factors.append('Multiple URLs found in file')
        if len(patterns.get('ips', [])) > 3:
            risk_factors.append('Multiple IP addresses found in file')
        
        # File characteristics
        metadata = analysis_results.get('metadata', {})
        if metadata.get('file_signature', {}).get('primary_type') == 'pe_executable':
            risk_factors.append('Executable file type')
        
        if metadata.get('size', 0) < 1024:
            risk_factors.append('Unusually small file size')
        
        return risk_factors
