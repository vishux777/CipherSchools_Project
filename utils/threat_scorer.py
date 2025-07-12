"""
Threat Scoring Module

Advanced threat scoring system that evaluates multiple indicators
to provide comprehensive threat assessment and risk scoring.
"""

import math
from typing import Dict, Any, List, Tuple
from collections import Counter

class ThreatScorer:
    """
    Advanced threat scoring engine for malware analysis
    """
    
    def __init__(self):
        """Initialize the threat scorer with scoring matrices"""
        self.entropy_weights = self._initialize_entropy_weights()
        self.pattern_weights = self._initialize_pattern_weights()
        self.api_weights = self._initialize_api_weights()
        self.virustotal_weights = self._initialize_virustotal_weights()
        self.file_type_weights = self._initialize_file_type_weights()
        
    def _initialize_entropy_weights(self) -> Dict[str, Dict[str, float]]:
        """Initialize entropy-based scoring weights"""
        return {
            'thresholds': {
                'very_high': 7.8,    # Extremely high entropy (packed/encrypted)
                'high': 7.0,         # High entropy (compressed/obfuscated)
                'moderate': 5.5,     # Moderate entropy (mixed content)
                'low': 3.0           # Low entropy (plain text/code)
            },
            'scores': {
                'very_high': 40,
                'high': 25,
                'moderate': 10,
                'low': 0
            }
        }
    
    def _initialize_pattern_weights(self) -> Dict[str, float]:
        """Initialize pattern-based scoring weights"""
        return {
            'bitcoin_addresses': 35,
            'ethereum_addresses': 30,
            'urls': 8,
            'emails': 5,
            'ip_addresses': 12,
            'file_paths': 3,
            'registry_keys': 15,
            'base64_data': 8,
            'hex_data': 5,
            'phone_numbers': 2,
            'credit_cards': 20,
            'social_security': 25,
            'passwords': 18
        }
    
    def _initialize_api_weights(self) -> Dict[str, float]:
        """Initialize API call pattern scoring weights"""
        return {
            'api_file_operations': 10,
            'api_registry_operations': 20,
            'api_process_operations': 25,
            'api_memory_operations': 30,
            'api_network_operations': 15,
            'api_crypto_operations': 35,
            'api_service_operations': 25,
            'api_debug_operations': 40,
            'api_injection_operations': 50,
            'api_persistence_operations': 30
        }
    
    def _initialize_virustotal_weights(self) -> Dict[str, Any]:
        """Initialize VirusTotal scoring weights"""
        return {
            'malicious_multiplier': 8,      # Each malicious detection adds this score
            'suspicious_multiplier': 3,     # Each suspicious detection adds this score
            'detection_ratio_bonus': {
                'very_high': 30,    # >50% detection ratio
                'high': 20,         # >25% detection ratio
                'medium': 10,       # >10% detection ratio
                'low': 0            # <10% detection ratio
            }
        }
    
    def _initialize_file_type_weights(self) -> Dict[str, float]:
        """Initialize file type risk scoring"""
        return {
            'pe_executable': 15,
            'elf_executable': 15,
            'script_batch': 20,
            'script_powershell': 25,
            'script_vbs': 20,
            'script_js': 15,
            'office_doc': 10,
            'pdf': 8,
            'java_class': 12,
            'unknown': 5
        }
    
    def calculate_score(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive threat score based on analysis data
        
        Args:
            analysis_data (dict): Complete analysis results
            
        Returns:
            dict: Detailed threat scoring results
        """
        try:
            # Initialize scoring components
            score_breakdown = {
                'entropy_score': 0,
                'pattern_score': 0,
                'api_score': 0,
                'virustotal_score': 0,
                'file_type_score': 0,
                'suspicious_indicators_score': 0,
                'size_anomaly_score': 0
            }
            
            reasons = []
            confidence_factors = []
            
            # Calculate individual component scores
            score_breakdown['entropy_score'], entropy_reasons = self._score_entropy(analysis_data)
            reasons.extend(entropy_reasons)
            
            score_breakdown['pattern_score'], pattern_reasons = self._score_patterns(analysis_data)
            reasons.extend(pattern_reasons)
            
            score_breakdown['api_score'], api_reasons = self._score_api_patterns(analysis_data)
            reasons.extend(api_reasons)
            
            score_breakdown['virustotal_score'], vt_reasons, vt_confidence = self._score_virustotal(analysis_data)
            reasons.extend(vt_reasons)
            confidence_factors.append(vt_confidence)
            
            score_breakdown['file_type_score'], filetype_reasons = self._score_file_type(analysis_data)
            reasons.extend(filetype_reasons)
            
            score_breakdown['suspicious_indicators_score'], indicator_reasons = self._score_suspicious_indicators(analysis_data)
            reasons.extend(indicator_reasons)
            
            score_breakdown['size_anomaly_score'], size_reasons = self._score_size_anomalies(analysis_data)
            reasons.extend(size_reasons)
            
            # Calculate total score
            total_score = sum(score_breakdown.values())
            
            # Apply score modifiers
            total_score, modifier_reasons = self._apply_score_modifiers(total_score, analysis_data)
            reasons.extend(modifier_reasons)
            
            # Cap score at 100
            final_score = min(total_score, 100)
            
            # Determine threat level
            threat_level = self._determine_threat_level(final_score)
            
            # Calculate confidence
            confidence = self._calculate_confidence(score_breakdown, confidence_factors)
            
            return {
                'level': threat_level,
                'score': round(final_score, 1),
                'confidence': confidence,
                'reasons': reasons[:15],  # Limit to top 15 reasons
                'score_breakdown': score_breakdown,
                'total_raw_score': round(total_score, 1),
                'risk_assessment': self._generate_risk_assessment(threat_level, final_score, confidence)
            }
            
        except Exception as e:
            return {
                'level': 'UNKNOWN',
                'score': 0,
                'confidence': 'low',
                'reasons': [f"Scoring error: {str(e)}"],
                'error': True
            }
    
    def _score_entropy(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on entropy analysis"""
        entropy_data = data.get('entropy', {})
        if not entropy_data:
            return 0, []
        
        score = 0
        reasons = []
        
        # Overall entropy scoring
        overall_entropy = entropy_data.get('overall_entropy', 0)
        if isinstance(overall_entropy, dict):
            overall_entropy = overall_entropy.get('overall_entropy', 0)
        
        thresholds = self.entropy_weights['thresholds']
        scores = self.entropy_weights['scores']
        
        if overall_entropy >= thresholds['very_high']:
            score += scores['very_high']
            reasons.append(f"Very high entropy ({overall_entropy:.2f}) suggests heavy encryption/packing")
        elif overall_entropy >= thresholds['high']:
            score += scores['high']
            reasons.append(f"High entropy ({overall_entropy:.2f}) indicates compression/obfuscation")
        elif overall_entropy >= thresholds['moderate']:
            score += scores['moderate']
            reasons.append(f"Moderate entropy ({overall_entropy:.2f}) shows mixed content")
        
        # High entropy sections bonus
        high_entropy_sections = entropy_data.get('high_entropy_sections', 0)
        if high_entropy_sections > 5:
            bonus = min(high_entropy_sections * 2, 20)
            score += bonus
            reasons.append(f"Multiple high-entropy sections detected ({high_entropy_sections})")
        
        return score, reasons
    
    def _score_patterns(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on pattern detection"""
        patterns = data.get('patterns', {})
        if not patterns:
            return 0, []
        
        score = 0
        reasons = []
        
        for pattern_type, matches in patterns.items():
            if matches and pattern_type in self.pattern_weights:
                pattern_score = self.pattern_weights[pattern_type]
                
                # Scale score based on number of matches
                if len(matches) > 5:
                    pattern_score *= 1.5
                elif len(matches) > 10:
                    pattern_score *= 2.0
                
                score += pattern_score
                reasons.append(f"{pattern_type.replace('_', ' ').title()}: {len(matches)} found")
        
        return score, reasons
    
    def _score_api_patterns(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on API call patterns"""
        patterns = data.get('patterns', {})
        if not patterns:
            return 0, []
        
        score = 0
        reasons = []
        
        for pattern_type, matches in patterns.items():
            if matches and pattern_type in self.api_weights:
                api_score = self.api_weights[pattern_type]
                
                # Critical APIs get higher scoring
                if pattern_type == 'api_injection_operations':
                    api_score *= 1.5
                elif pattern_type == 'api_debug_operations':
                    api_score *= 1.3
                
                score += api_score
                reasons.append(f"{pattern_type.replace('api_', '').replace('_', ' ').title()} APIs detected")
        
        return score, reasons
    
    def _score_virustotal(self, data: Dict[str, Any]) -> Tuple[float, List[str], str]:
        """Score based on VirusTotal results"""
        vt_data = data.get('virustotal', {})
        if 'error' in vt_data or not vt_data:
            return 0, [], 'low'
        
        score = 0
        reasons = []
        confidence = 'high'
        
        stats = vt_data.get('stats', {})
        if not stats:
            return 0, [], 'low'
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = stats.get('total', 1)
        
        # Score based on detections
        malicious_score = malicious * self.virustotal_weights['malicious_multiplier']
        suspicious_score = suspicious * self.virustotal_weights['suspicious_multiplier']
        
        score += malicious_score + suspicious_score
        
        if malicious > 0:
            reasons.append(f"VirusTotal: {malicious} engines detected malware")
        if suspicious > 0:
            reasons.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
        
        # Detection ratio bonus
        detection_ratio = (malicious + suspicious) / max(total, 1)
        ratio_bonus = self.virustotal_weights['detection_ratio_bonus']
        
        if detection_ratio > 0.5:
            score += ratio_bonus['very_high']
            reasons.append(f"Very high detection ratio ({detection_ratio*100:.1f}%)")
        elif detection_ratio > 0.25:
            score += ratio_bonus['high']
            reasons.append(f"High detection ratio ({detection_ratio*100:.1f}%)")
        elif detection_ratio > 0.1:
            score += ratio_bonus['medium']
            reasons.append(f"Moderate detection ratio ({detection_ratio*100:.1f}%)")
        
        # Adjust confidence based on total engines
        if total < 10:
            confidence = 'low'
        elif total < 30:
            confidence = 'medium'
        else:
            confidence = 'high'
        
        return score, reasons, confidence
    
    def _score_file_type(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on file type and signature analysis"""
        file_signature = data.get('file_signature', {})
        if not file_signature:
            return 0, []
        
        score = 0
        reasons = []
        
        detected_types = file_signature.get('detected_types', [])
        for file_type in detected_types:
            if file_type in self.file_type_weights:
                type_score = self.file_type_weights[file_type]
                score += type_score
                reasons.append(f"File type: {file_type.replace('_', ' ').title()}")
        
        # Signature mismatch penalty
        file_info = data.get('file_info', {})
        if file_info:
            extension = file_info.get('extension', '').lower()
            primary_type = file_signature.get('primary_type', 'unknown')
            
            # Check for common mismatches
            mismatch_detected = False
            if extension == '.txt' and primary_type == 'pe_executable':
                mismatch_detected = True
            elif extension == '.pdf' and primary_type != 'pdf':
                mismatch_detected = True
            elif extension == '.doc' and primary_type != 'office_doc':
                mismatch_detected = True
            
            if mismatch_detected:
                score += 25
                reasons.append(f"File extension mismatch: {extension} vs {primary_type}")
        
        return score, reasons
    
    def _score_suspicious_indicators(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on suspicious indicators"""
        indicators = data.get('suspicious_indicators', [])
        if not indicators:
            return 0, []
        
        score = 0
        reasons = []
        
        severity_scores = {'high': 20, 'medium': 10, 'low': 5}
        
        for indicator in indicators:
            severity = indicator.get('severity', 'low')
            indicator_score = severity_scores.get(severity, 5)
            score += indicator_score
            
            description = indicator.get('description', 'Unknown indicator')
            reasons.append(f"{severity.upper()}: {description}")
        
        return score, reasons
    
    def _score_size_anomalies(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Score based on file size anomalies"""
        file_size = data.get('file_size', 0)
        if file_size == 0:
            return 0, []
        
        score = 0
        reasons = []
        
        # Very small executable files are suspicious
        file_signature = data.get('file_signature', {})
        detected_types = file_signature.get('detected_types', [])
        
        if any(t in detected_types for t in ['pe_executable', 'elf_executable']) and file_size < 1024:
            score += 15
            reasons.append(f"Unusually small executable ({file_size} bytes)")
        
        # Very large files might contain embedded content
        if file_size > 50 * 1024 * 1024:  # 50MB
            score += 10
            reasons.append(f"Large file size ({file_size} bytes) may contain embedded content")
        
        return score, reasons
    
    def _apply_score_modifiers(self, score: float, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Apply additional score modifiers based on combinations"""
        modified_score = score
        reasons = []
        
        patterns = data.get('patterns', {})
        
        # Combination bonuses
        has_crypto = bool(patterns.get('bitcoin_addresses') or patterns.get('ethereum_addresses'))
        has_injection = bool(patterns.get('api_injection_operations'))
        has_persistence = bool(patterns.get('api_persistence_operations'))
        has_anti_debug = bool(patterns.get('api_debug_operations'))
        
        # Crypto + injection combo (ransomware pattern)
        if has_crypto and has_injection:
            modified_score *= 1.3
            reasons.append("Cryptocurrency + injection pattern (potential ransomware)")
        
        # Persistence + anti-debugging (advanced malware)
        if has_persistence and has_anti_debug:
            modified_score *= 1.2
            reasons.append("Persistence + anti-debugging (sophisticated threat)")
        
        # Multiple API categories (complex malware)
        api_categories = len([k for k in patterns.keys() if k.startswith('api_') and patterns[k]])
        if api_categories >= 5:
            modified_score *= 1.1
            reasons.append(f"Multiple API categories used ({api_categories})")
        
        return modified_score, reasons
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level based on final score"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 35:
            return 'MEDIUM'
        elif score >= 15:
            return 'LOW'
        else:
            return 'CLEAN'
    
    def _calculate_confidence(self, score_breakdown: Dict[str, float], confidence_factors: List[str]) -> str:
        """Calculate overall confidence in the assessment"""
        # Count non-zero scoring components
        active_components = sum([server])
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "#ff4b4b"
backgroundColor = "#0e1117"
secondaryBackgroundColor = "#262730"
textColor = "#fafafa"
base = "dark"
