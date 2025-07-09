from typing import Dict, List, Any

class ThreatScorer:
    """Advanced threat scoring system for malware analysis results"""
    
    def __init__(self):
        # Scoring weights for different components
        self.weights = {
            'entropy': 0.2,
            'strings': 0.15,
            'patterns': 0.2,
            'metadata': 0.15,
            'suspicious_patterns': 0.3
        }
        
        # VirusTotal scoring weights
        self.vt_weights = {
            'reputation': 0.4,
            'detection_ratio': 0.6
        }
    
    def calculate_static_threat_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat score from static analysis results"""
        scores = {}
        
        # Score entropy
        if 'entropy' in analysis_results:
            scores['entropy'] = self._score_entropy(analysis_results['entropy'])
        
        # Score strings
        if 'strings' in analysis_results:
            scores['strings'] = self._score_strings(analysis_results['strings'])
        
        # Score patterns
        if 'patterns' in analysis_results:
            scores['patterns'] = self._score_patterns(analysis_results['patterns'])
        
        # Score metadata
        if 'metadata' in analysis_results:
            scores['metadata'] = self._score_metadata(analysis_results['metadata'])
        
        # Score suspicious patterns
        if 'suspicious_patterns' in analysis_results:
            scores['suspicious_patterns'] = self._score_suspicious_patterns(analysis_results['suspicious_patterns'])
        
        # Calculate weighted overall score
        overall_score = 0
        total_weight = 0
        
        for component, score in scores.items():
            if component in self.weights:
                overall_score += score * self.weights[component]
                total_weight += self.weights[component]
        
        if total_weight > 0:
            overall_score = overall_score / total_weight * 100
        
        # Determine threat level
        threat_level = self._get_threat_level(overall_score)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(analysis_results, scores)
        
        return {
            'overall_score': overall_score,
            'threat_level': threat_level,
            'component_scores': scores,
            'risk_factors': risk_factors,
            'scoring_method': 'static_analysis'
        }
    
    def calculate_virustotal_threat_score(self, vt_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat score from VirusTotal results"""
        if 'data' not in vt_results:
            return {
                'overall_score': 0,
                'threat_level': 'unknown',
                'component_scores': {},
                'risk_factors': [],
                'scoring_method': 'virustotal'
            }
        
        data = vt_results['data']['attributes']
        scores = {}
        
        # Score reputation
        reputation_score = self._score_vt_reputation(data)
        scores['reputation'] = reputation_score
        
        # Score detection ratio
        stats = data.get('last_analysis_stats', {})
        total_engines = sum(stats.values()) if stats else 0
        malicious_count = stats.get('malicious', 0)
        
        if total_engines > 0:
            detection_ratio = (malicious_count / total_engines) * 100
            scores['detection_ratio'] = detection_ratio
        else:
            scores['detection_ratio'] = 0
        
        # Calculate weighted overall score
        overall_score = (
            scores['reputation'] * self.vt_weights['reputation'] +
            scores['detection_ratio'] * self.vt_weights['detection_ratio']
        )
        
        # Determine threat level
        threat_level = self._get_threat_level(overall_score)
        
        # Analyze engine detections for additional insights
        engine_analysis = self._analyze_engine_detections(data.get('last_analysis_results', {}))
        
        return {
            'overall_score': overall_score,
            'threat_level': threat_level,
            'component_scores': scores,
            'risk_factors': engine_analysis.get('risk_factors', []),
            'engine_analysis': engine_analysis,
            'scoring_method': 'virustotal'
        }
    
    def _score_entropy(self, entropy: float) -> float:
        """Score file entropy (0-100)"""
        if entropy >= 7:
            return 80
        elif entropy >= 6:
            return 50
        else:
            return 20
    
    def _score_strings(self, strings: List[str]) -> float:
        """Score string analysis results (0-100)"""
        if not strings:
            return 0
        
        suspicious_keywords = [
            'password', 'keylog', 'backdoor', 'trojan', 'virus',
            'malware', 'exploit', 'shell', 'cmd', 'powershell',
            'download', 'execute', 'inject', 'decrypt', 'encrypt'
        ]
        
        score = 0
        for string_item in strings:
            string_lower = string_item.lower()
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    score += 10
        
        return min(score, 100)
    
    def _score_patterns(self, patterns: Dict[str, List[str]]) -> float:
        """Score pattern detection results (0-100)"""
        score = 0
        
        if patterns.get('urls'):
            score += len(patterns['urls']) * 15
        if patterns.get('ip_addresses'):
            score += len(patterns['ip_addresses']) * 10
        if patterns.get('email_addresses'):
            score += len(patterns['email_addresses']) * 5
        if patterns.get('registry_keys'):
            score += len(patterns['registry_keys']) * 20
        if patterns.get('bitcoin_addresses'):
            score += len(patterns['bitcoin_addresses']) * 25
        
        return min(score, 100)
    
    def _score_metadata(self, metadata: Dict[str, Any]) -> float:
        """Score file metadata (0-100)"""
        score = 0
        
        file_sig = metadata.get('file_signature', {})
        if file_sig.get('is_pe'):
            score += 30
        if metadata.get('is_archive'):
            score += 20
        
        file_type = metadata.get('file_type', '').lower()
        if any(script_type in file_type for script_type in ['javascript', 'powershell', 'batch', 'script']):
            score += 25
        
        return min(score, 100)
    
    def _score_suspicious_patterns(self, suspicious_patterns: Dict[str, List[str]]) -> float:
        """Score suspicious pattern analysis (0-100)"""
        score = 0
        
        score += len(suspicious_patterns.get('suspicious_api_calls', [])) * 15
        score += len(suspicious_patterns.get('obfuscation_indicators', [])) * 10
        score += len(suspicious_patterns.get('persistence_indicators', [])) * 20
        score += len(suspicious_patterns.get('network_indicators', [])) * 12
        score += len(suspicious_patterns.get('crypto_indicators', [])) * 8
        
        return min(score, 100)
    
    def _score_vt_reputation(self, vt_data: Dict[str, Any]) -> float:
        """Score VirusTotal reputation data (0-100)"""
        stats = vt_data.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        
        total = malicious + suspicious + harmless + undetected
        
        if total == 0:
            return 0
        
        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total
        
        score = (malicious_ratio * 100) + (suspicious_ratio * 60)
        
        return min(score, 100)
    
    def _analyze_engine_detections(self, engine_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual engine detection patterns"""
        analysis = {
            'total_engines': len(engine_results),
            'detection_categories': {},
            'common_detection_names': [],
            'risk_factors': []
        }
        
        categories = {}
        detection_names = []
        
        for engine, result in engine_results.items():
            category = result.get('category', 'undetected')
            detection_name = result.get('result')
            
            categories[category] = categories.get(category, 0) + 1
            
            if detection_name and detection_name.lower() != 'clean':
                detection_names.append(detection_name)
        
        analysis['detection_categories'] = categories
        
        if detection_names:
            from collections import Counter
            name_counts = Counter(detection_names)
            analysis['common_detection_names'] = [name for name, count in name_counts.most_common(5)]
        
        if categories.get('malicious', 0) > 5:
            analysis['risk_factors'].append('High malicious detection count')
        if categories.get('suspicious', 0) > 3:
            analysis['risk_factors'].append('Multiple suspicious detections')
        
        return analysis
    
    def _get_threat_level(self, score: float) -> str:
        """Convert numerical score to threat level"""
        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 10:
            return 'low'
        else:
            return 'minimal'
    
    def _identify_risk_factors(self, analysis_results: Dict[str, Any], scores: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors from analysis"""
        risk_factors = []
        
        if analysis_results.get('entropy', 0) > 7:
            risk_factors.append('High file entropy (likely packed/encrypted)')
        
        suspicious_patterns = analysis_results.get('suspicious_patterns', {})
        api_calls = suspicious_patterns.get('suspicious_api_calls', [])
        if api_calls:
            risk_factors.append(f'Suspicious API calls detected: {", ".join(api_calls[:3])}')
        
        if suspicious_patterns.get('network_indicators', []):
            risk_factors.append('Network communication capabilities detected')
        
        if suspicious_patterns.get('persistence_indicators', []):
            risk_factors.append('Persistence mechanisms detected')
        
        if suspicious_patterns.get('obfuscation_indicators', []):
            risk_factors.append('Code obfuscation detected')
        
        return risk_factors