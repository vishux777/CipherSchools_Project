"""
Threat Scoring Module
Advanced threat assessment and scoring algorithms
"""

import math
import json
from datetime import datetime
from collections import Counter

class ThreatScorer:
    """
    Advanced threat scoring system with multiple algorithms
    """
    
    def __init__(self):
        """Initialize the threat scorer"""
        self.scoring_weights = {
            'entropy': 0.25,
            'patterns': 0.30,
            'behavioral': 0.25,
            'metadata': 0.10,
            'strings': 0.10
        }
        
        self.threat_thresholds = {
            'low': 30,
            'medium': 50,
            'high': 70,
            'critical': 85
        }
        
        # Known malware family indicators
        self.malware_families = {
            'ransomware': {
                'keywords': ['encrypt', 'decrypt', 'ransom', 'bitcoin', 'unlock', 'payment'],
                'apis': ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey'],
                'patterns': [r'\.encrypted', r'\.locked', 'HOW_TO_DECRYPT'],
                'weight': 40
            },
            'trojan': {
                'keywords': ['backdoor', 'remote', 'control', 'command'],
                'apis': ['CreateRemoteThread', 'WriteProcessMemory', 'SetWindowsHookEx'],
                'patterns': [r'cmd\.exe', r'powershell\.exe'],
                'weight': 35
            },
            'spyware': {
                'keywords': ['keylog', 'monitor', 'capture', 'steal'],
                'apis': ['GetAsyncKeyState', 'SetWindowsHookEx', 'GetWindowText'],
                'patterns': ['passwords', 'credentials', 'browser'],
                'weight': 30
            },
            'worm': {
                'keywords': ['spread', 'propagate', 'network', 'share'],
                'apis': ['WNetAddConnection', 'WNetEnumResource', 'CreateFile'],
                'patterns': [r'autorun\.inf', 'usb', 'removable'],
                'weight': 25
            },
            'adware': {
                'keywords': ['advertisement', 'popup', 'browser', 'homepage'],
                'apis': ['InternetOpen', 'InternetConnect', 'RegSetValue'],
                'patterns': ['ads', 'popup', 'toolbar'],
                'weight': 15
            }
        }
    
    def calculate_threat_score(self, analysis_results):
        """
        Calculate comprehensive threat score
        
        Args:
            analysis_results (dict): Complete analysis results
            
        Returns:
            dict: Threat score and assessment
        """
        try:
            # Calculate component scores
            component_scores = {
                'entropy_score': self._score_entropy(analysis_results),
                'pattern_score': self._score_patterns(analysis_results),
                'behavioral_score': self._score_behavioral(analysis_results),
                'metadata_score': self._score_metadata(analysis_results),
                'string_score': self._score_strings(analysis_results)
            }
            
            # Calculate weighted total score
            total_score = 0
            for component, score in component_scores.items():
                weight_key = component.replace('_score', '')
                weight = self.scoring_weights.get(weight_key, 0)
                total_score += score * weight
            
            # Malware family detection
            family_assessment = self._assess_malware_family(analysis_results)
            if family_assessment['detected']:
                total_score += family_assessment['bonus_score']
            
            # Normalize score to 0-100 range
            total_score = min(max(total_score, 0), 100)
            
            # Determine threat level
            threat_level = self._determine_threat_level(total_score)
            
            # Calculate confidence
            confidence = self._calculate_confidence(analysis_results, component_scores)
            
            # Generate detailed assessment
            assessment = {
                'total_score': round(total_score, 2),
                'threat_level': threat_level,
                'confidence': confidence,
                'component_scores': component_scores,
                'malware_family': family_assessment,
                'risk_factors': self._identify_risk_factors(analysis_results),
                'mitigation_priority': self._calculate_mitigation_priority(total_score, confidence),
                'false_positive_likelihood': self._estimate_false_positive_likelihood(analysis_results),
                'recommendation': self._generate_recommendation(threat_level, total_score, confidence)
            }
            
            return assessment
        
        except Exception as e:
            return {
                'error': f"Threat scoring failed: {str(e)}",
                'total_score': 0,
                'threat_level': 'UNKNOWN',
                'confidence': 'low'
            }
    
    def _score_entropy(self, results):
        """Score entropy-based indicators"""
        if 'entropy' not in results:
            return 0
        
        entropy_data = results['entropy']
        score = 0
        
        # Overall entropy scoring
        overall_entropy = entropy_data.get('overall_entropy', 0)
        if overall_entropy > 7.8:
            score += 35  # Very high entropy
        elif overall_entropy > 7.5:
            score += 25  # High entropy
        elif overall_entropy > 7.0:
            score += 15  # Moderate entropy
        elif overall_entropy > 6.5:
            score += 10  # Slightly elevated entropy
        
        # High entropy sections
        high_entropy_sections = entropy_data.get('high_entropy_sections', [])
        if len(high_entropy_sections) > 0:
            score += min(len(high_entropy_sections) * 5, 20)
        
        # Entropy variance (indicates packing/encryption)
        entropy_variance = entropy_data.get('entropy_variance', 0)
        if entropy_variance > 1.0:
            score += 10
        
        # Assessment indicators
        assessment = entropy_data.get('assessment', {})
        if assessment.get('likely_packed'):
            score += 15
        if assessment.get('likely_encrypted'):
            score += 20
        
        return min(score, 100)
    
    def _score_patterns(self, results):
        """Score pattern-based indicators"""
        if 'patterns' not in results:
            return 0
        
        patterns = results['patterns']
        score = 0
        
        # Pattern category scoring
        category_weights = {
            'suspicious_apis': 25,
            'crypto_indicators': 20,
            'network_indicators': 15,
            'registry_operations': 15,
            'file_operations': 10,
            'persistence_mechanisms': 20
        }
        
        for category, weight in category_weights.items():
            if category in patterns and patterns[category]:
                # Score based on number of matches
                matches = len(patterns[category])
                category_score = min(matches * 5, weight)
                score += category_score
        
        # Pattern statistics
        pattern_stats = patterns.get('pattern_statistics', {})
        total_patterns = pattern_stats.get('total_patterns', 0)
        if total_patterns > 50:
            score += 15
        elif total_patterns > 20:
            score += 10
        elif total_patterns > 10:
            score += 5
        
        return min(score, 100)
    
    def _score_behavioral(self, results):
        """Score behavioral indicators"""
        if 'behavioral' not in results:
            return 0
        
        behavioral = results['behavioral']
        score = behavioral.get('score', 0)
        
        # Behavioral indicators scoring
        indicators = behavioral.get('indicators', {})
        
        # Weight different behavior categories
        behavior_weights = {
            'persistence_mechanisms': 20,
            'network_activity': 15,
            'file_operations': 10,
            'registry_operations': 15,
            'process_operations': 20,
            'evasion_techniques': 30
        }
        
        for category, weight in behavior_weights.items():
            if category in indicators and indicators[category]:
                matches = len(indicators[category])
                category_score = min(matches * 3, weight)
                score += category_score
        
        return min(score, 100)
    
    def _score_metadata(self, results):
        """Score metadata-based indicators"""
        if 'metadata' not in results:
            return 0
        
        metadata = results['metadata']
        score = 0
        
        # Filename analysis
        filename_analysis = metadata.get('filename_analysis', {})
        if filename_analysis.get('suspicious_extension'):
            score += 15
        if filename_analysis.get('double_extension'):
            score += 20
        if filename_analysis.get('suspicious_keywords'):
            score += len(filename_analysis['suspicious_keywords']) * 5
        
        # File size analysis
        file_size_analysis = metadata.get('file_size_analysis', {})
        if file_size_analysis.get('suspicious_size'):
            score += 10
        
        # Creation indicators
        creation_indicators = metadata.get('creation_indicators', {})
        if creation_indicators.get('build_tools'):
            # Some build tools might be suspicious
            suspicious_tools = ['AutoIt', 'NSIS', 'Inno Setup']
            for tool in creation_indicators['build_tools']:
                if tool in suspicious_tools:
                    score += 10
        
        return min(score, 100)
    
    def _score_strings(self, results):
        """Score string-based indicators"""
        if 'strings' not in results:
            return 0
        
        strings_data = results['strings']
        score = 0
        
        # Interesting strings scoring
        interesting_strings = strings_data.get('interesting_strings', {})
        
        string_weights = {
            'suspicious_keywords': 15,
            'api_calls': 10,
            'registry_keys': 10,
            'file_paths': 5,
            'urls': 8,
            'emails': 5,
            'ip_addresses': 8
        }
        
        for category, weight in string_weights.items():
            if category in interesting_strings and interesting_strings[category]:
                matches = len(interesting_strings[category])
                category_score = min(matches * 2, weight)
                score += category_score
        
        # String statistics
        string_stats = strings_data.get('string_statistics', {})
        total_strings = string_stats.get('total_count', 0)
        
        # Very few strings might indicate packing
        if total_strings < 10:
            score += 10
        
        # Very many strings might indicate data or resources
        if total_strings > 1000:
            score += 5
        
        return min(score, 100)
    
    def _assess_malware_family(self, results):
        """Assess potential malware family"""
        family_scores = {}
        
        # Convert results to searchable text
        searchable_text = self._extract_searchable_text(results)
        
        # Score each malware family
        for family_name, family_data in self.malware_families.items():
            family_score = 0
            indicators_found = []
            
            # Check keywords
            for keyword in family_data['keywords']:
                if keyword.lower() in searchable_text.lower():
                    family_score += 5
                    indicators_found.append(f"keyword: {keyword}")
            
            # Check APIs
            for api in family_data['apis']:
                if api.lower() in searchable_text.lower():
                    family_score += 8
                    indicators_found.append(f"api: {api}")
            
            # Check patterns
            import re
            for pattern in family_data['patterns']:
                if re.search(pattern, searchable_text, re.IGNORECASE):
                    family_score += 10
                    indicators_found.append(f"pattern: {pattern}")
            
            if family_score > 0:
                family_scores[family_name] = {
                    'score': family_score,
                    'indicators': indicators_found,
                    'confidence': self._calculate_family_confidence(family_score)
                }
        
        # Determine most likely family
        if family_scores:
            top_family = max(family_scores.keys(), key=lambda x: family_scores[x]['score'])
            top_score = family_scores[top_family]['score']
            
            return {
                'detected': True,
                'most_likely_family': top_family,
                'confidence': family_scores[top_family]['confidence'],
                'all_families': family_scores,
                'bonus_score': min(top_score, self.malware_families[top_family]['weight'])
            }
        
        return {
            'detected': False,
            'most_likely_family': None,
            'confidence': 'none',
            'all_families': {},
            'bonus_score': 0
        }
    
    def _extract_searchable_text(self, results):
        """Extract searchable text from all results"""
        text_parts = []
        
        # Add filename
        if 'filename' in results:
            text_parts.append(results['filename'])
        
        # Add strings
        if 'strings' in results:
            strings_data = results['strings']
            if 'ascii_strings' in strings_data:
                text_parts.extend(strings_data['ascii_strings'])
            if 'unicode_strings' in strings_data:
                text_parts.extend(strings_data['unicode_strings'])
        
        # Add patterns
        if 'patterns' in results:
            patterns = results['patterns']
            for category, matches in patterns.items():
                if isinstance(matches, list):
                    text_parts.extend(matches)
        
        # Add behavioral indicators
        if 'behavioral' in results:
            behavioral = results['behavioral'].get('indicators', {})
            for category, indicators in behavioral.items():
                if isinstance(indicators, list):
                    text_parts.extend(indicators)
        
        return ' '.join(str(part) for part in text_parts)
    
    def _calculate_family_confidence(self, score):
        """Calculate confidence for malware family detection"""
        if score >= 30:
            return 'high'
        elif score >= 15:
            return 'medium'
        elif score >= 5:
            return 'low'
        else:
            return 'none'
    
    def _determine_threat_level(self, score):
        """Determine threat level based on score"""
        if score >= self.threat_thresholds['critical']:
            return 'CRITICAL'
        elif score >= self.threat_thresholds['high']:
            return 'HIGH'
        elif score >= self.threat_thresholds['medium']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_confidence(self, results, component_scores):
        """Calculate overall confidence in the assessment"""
        factors = 0
        total_weight = 0
        
        # Check which analysis modules were successful
        for component, score in component_scores.items():
            if score > 0:
                factors += 1
                total_weight += score
        
        # More factors and higher scores = higher confidence
        if factors >= 4 and total_weight > 50:
            return 'high'
        elif factors >= 3 and total_weight > 25:
            return 'medium'
        elif factors >= 2:
            return 'low'
        else:
            return 'very_low'
    
    def _identify_risk_factors(self, results):
        """Identify specific risk factors"""
        risk_factors = []
        
        # Entropy risks
        if 'entropy' in results:
            entropy_data = results['entropy']
            if entropy_data.get('overall_entropy', 0) > 7.5:
                risk_factors.append("High entropy indicates possible packing/encryption")
            if entropy_data.get('assessment', {}).get('likely_packed'):
                risk_factors.append("File appears to be packed")
        
        # Pattern risks
        if 'patterns' in results:
            patterns = results['patterns']
            if patterns.get('suspicious_apis'):
                risk_factors.append("Contains suspicious API calls")
            if patterns.get('crypto_indicators'):
                risk_factors.append("Contains cryptocurrency-related indicators")
            if patterns.get('network_indicators'):
                risk_factors.append("Contains network communication indicators")
        
        # Behavioral risks
        if 'behavioral' in results:
            behavioral = results['behavioral']
            if behavioral.get('score', 0) > 50:
                risk_factors.append("High behavioral risk score")
            
            indicators = behavioral.get('indicators', {})
            if indicators.get('persistence_mechanisms'):
                risk_factors.append("Contains persistence mechanisms")
            if indicators.get('evasion_techniques'):
                risk_factors.append("Contains evasion techniques")
        
        # Metadata risks
        if 'metadata' in results:
            metadata = results['metadata']
            filename_analysis = metadata.get('filename_analysis', {})
            if filename_analysis.get('double_extension'):
                risk_factors.append("File has double extension")
            if filename_analysis.get('suspicious_keywords'):
                risk_factors.append("Filename contains suspicious keywords")
        
        return risk_factors
    
    def _calculate_mitigation_priority(self, score, confidence):
        """Calculate mitigation priority"""
        if score >= 80 and confidence in ['high', 'medium']:
            return 'IMMEDIATE'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _estimate_false_positive_likelihood(self, results):
        """Estimate likelihood of false positive"""
        # Factors that increase false positive likelihood
        fp_factors = 0
        
        # Very high entropy but no other indicators
        if 'entropy' in results:
            entropy_data = results['entropy']
            if entropy_data.get('overall_entropy', 0) > 7.8:
                # Check if there are other strong indicators
                if not self._has_strong_indicators(results):
                    fp_factors += 1
        
        # Only metadata indicators
        if self._only_metadata_indicators(results):
            fp_factors += 1
        
        # Very few patterns detected
        if 'patterns' in results:
            pattern_stats = results['patterns'].get('pattern_statistics', {})
            if pattern_stats.get('total_patterns', 0) < 3:
                fp_factors += 1
        
        # Calculate likelihood
        if fp_factors >= 2:
            return 'high'
        elif fp_factors == 1:
            return 'medium'
        else:
            return 'low'
    
    def _has_strong_indicators(self, results):
        """Check if results have strong malware indicators"""
        strong_indicators = False
        
        # Strong behavioral indicators
        if 'behavioral' in results:
            behavioral = results['behavioral']
            if behavioral.get('score', 0) > 40:
                strong_indicators = True
        
        # Multiple suspicious patterns
        if 'patterns' in results:
            patterns = results['patterns']
            suspicious_count = sum(1 for category in ['suspicious_apis', 'crypto_indicators', 'network_indicators'] 
                                 if patterns.get(category))
            if suspicious_count >= 2:
                strong_indicators = True
        
        return strong_indicators
    
    def _only_metadata_indicators(self, results):
        """Check if only metadata indicators are present"""
        has_metadata = 'metadata' in results
        has_other_indicators = any(key in results for key in ['patterns', 'behavioral', 'entropy'])
        
        return has_metadata and not has_other_indicators
    
    def _generate_recommendation(self, threat_level, score, confidence):
        """Generate recommendation based on assessment"""
        recommendations = {
            'CRITICAL': "IMMEDIATE ACTION REQUIRED: Quarantine file immediately. Do not execute under any circumstances. Submit to security team for analysis.",
            'HIGH': "HIGH RISK: Exercise extreme caution. Analyze in isolated environment only. Verify source before any action.",
            'MEDIUM': "MODERATE RISK: Additional verification recommended. Consider scanning with multiple engines.",
            'LOW': "LOW RISK: File appears relatively safe, but maintain standard security practices."
        }
        
        base_recommendation = recommendations.get(threat_level, "Unable to determine risk level.")
        
        # Adjust based on confidence
        if confidence == 'low':
            base_recommendation += " Note: Analysis confidence is low - consider additional verification."
        elif confidence == 'very_low':
            base_recommendation += " Note: Analysis confidence is very low - results may not be reliable."
        
        return base_recommendation
    
    def create_scoring_report(self, analysis_results):
        """Create a detailed scoring report"""
        assessment = self.calculate_threat_score(analysis_results)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'file_name': analysis_results.get('filename', 'Unknown'),
            'overall_assessment': {
                'threat_level': assessment['threat_level'],
                'total_score': assessment['total_score'],
                'confidence': assessment['confidence'],
                'recommendation': assessment['recommendation']
            },
            'detailed_scoring': {
                'component_scores': assessment['component_scores'],
                'scoring_weights': self.scoring_weights,
                'threshold_levels': self.threat_thresholds
            },
            'risk_analysis': {
                'risk_factors': assessment['risk_factors'],
                'mitigation_priority': assessment['mitigation_priority'],
                'false_positive_likelihood': assessment['false_positive_likelihood']
            },
            'malware_family_assessment': assessment['malware_family']
        }
        
        return report
