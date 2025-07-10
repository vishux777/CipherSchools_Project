"""
Advanced Analysis Engine
Comprehensive file analysis and threat detection
"""

import hashlib
import math
import string
import re
import json
import time
from datetime import datetime
from collections import Counter
import os

class AnalysisEngine:
    """
    Advanced malware analysis engine with multiple detection methods
    """
    
    def __init__(self):
        """Initialize the analysis engine"""
        self.analysis_modules = {
            'hash_analysis': self._analyze_hashes,
            'entropy_analysis': self._analyze_entropy,
            'string_extraction': self._extract_strings,
            'pattern_detection': self._detect_patterns,
            'behavioral_analysis': self._behavioral_analysis,
            'metadata_analysis': self._analyze_metadata
        }
        
        # Suspicious patterns for detection
        self.suspicious_patterns = {
            'registry_keys': [
                r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                r'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ],
            'suspicious_apis': [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
                'VirtualAlloc', 'VirtualProtect', 'CreateProcess',
                'ShellExecute', 'WinExec', 'RegCreateKey', 'RegSetValue',
                'CryptEncrypt', 'CryptDecrypt', 'InternetOpen', 'InternetConnect'
            ],
            'crypto_indicators': [
                'bitcoin', 'btc', 'wallet', 'cryptocurrency', 'mining',
                'private.*key', 'public.*key', 'encryption', 'cipher',
                'ransomware', 'decrypt', 'unlock.*files'
            ],
            'network_indicators': [
                r'https?://[^\s<>"]+',
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'ftp://[^\s<>"]+',
                r'\.onion\b'
            ],
            'file_operations': [
                'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
                'MoveFile', 'CopyFile', 'FindFirstFile', 'FindNextFile'
            ],
            'persistence_mechanisms': [
                'CreateService', 'OpenService', 'StartService',
                'ControlService', 'QueryServiceStatus', 'CreateMutex',
                'OpenMutex', 'ReleaseMutex'
            ]
        }
        
        # Known malware file signatures
        self.malware_signatures = {
            'MZ': 'PE Executable',
            'PK': 'ZIP Archive',
            'PDF': 'PDF Document',
            '7z': '7-Zip Archive',
            'Rar!': 'RAR Archive'
        }
    
    def analyze_file(self, file_data, filename, config=None):
        """
        Perform comprehensive file analysis
        
        Args:
            file_data (bytes): File content as bytes
            filename (str): Name of the file
            config (dict): Analysis configuration
            
        Returns:
            dict: Complete analysis results
        """
        if config is None:
            config = self._get_default_config()
        
        try:
            # Initialize results
            results = {
                'filename': filename,
                'file_size': len(file_data),
                'analysis_time': datetime.now().isoformat(),
                'analysis_duration': 0,
                'modules_run': [],
                'errors': []
            }
            
            start_time = time.time()
            
            # Run enabled analysis modules
            for module_name, module_func in self.analysis_modules.items():
                if config.get(module_name, True):
                    try:
                        module_results = module_func(file_data, filename, config)
                        results.update(module_results)
                        results['modules_run'].append(module_name)
                    except Exception as e:
                        error_msg = f"Error in {module_name}: {str(e)}"
                        results['errors'].append(error_msg)
            
            # Calculate analysis duration
            results['analysis_duration'] = time.time() - start_time
            
            # Generate threat assessment
            results['threat_assessment'] = self._assess_threat(results, config)
            
            return results
        
        except Exception as e:
            return {
                'error': f"Analysis failed: {str(e)}",
                'filename': filename,
                'file_size': len(file_data) if file_data else 0,
                'analysis_time': datetime.now().isoformat()
            }
    
    def _get_default_config(self):
        """Get default analysis configuration"""
        return {
            'hash_analysis': True,
            'entropy_analysis': True,
            'string_extraction': True,
            'pattern_detection': True,
            'behavioral_analysis': True,
            'metadata_analysis': True,
            'max_strings': 200,
            'min_string_length': 4,
            'sensitivity_level': 'Medium'
        }
    
    def _analyze_hashes(self, file_data, filename, config):
        """
        Calculate and analyze file hashes
        
        Args:
            file_data (bytes): File content
            filename (str): File name
            config (dict): Configuration
            
        Returns:
            dict: Hash analysis results
        """
        hashes = {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'ssdeep': self._calculate_fuzzy_hash(file_data)
        }
        
        # Check against known malware hashes (placeholder)
        hash_reputation = self._check_hash_reputation(hashes)
        
        return {
            'hashes': hashes,
            'hash_reputation': hash_reputation
        }
    
    def _calculate_fuzzy_hash(self, file_data):
        """
        Calculate fuzzy hash (simplified implementation)
        
        Args:
            file_data (bytes): File content
            
        Returns:
            str: Fuzzy hash
        """
        # Simplified fuzzy hash implementation
        # In production, use ssdeep library
        chunk_size = 64
        chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
        chunk_hashes = [hashlib.md5(chunk).hexdigest()[:8] for chunk in chunks]
        return ':'.join(chunk_hashes[:10])  # Limit to first 10 chunks
    
    def _check_hash_reputation(self, hashes):
        """
        Check hash reputation against known databases
        
        Args:
            hashes (dict): File hashes
            
        Returns:
            dict: Reputation information
        """
        # Placeholder for hash reputation checking
        # In production, integrate with threat intelligence feeds
        return {
            'known_malware': False,
            'reputation_score': 0,
            'sources': []
        }
    
    def _analyze_entropy(self, file_data, filename, config):
        """
        Analyze file entropy for encryption/packing detection
        
        Args:
            file_data (bytes): File content
            filename (str): File name
            config (dict): Configuration
            
        Returns:
            dict: Entropy analysis results
        """
        # Calculate overall entropy
        overall_entropy = self._calculate_entropy(file_data)
        
        # Calculate entropy for different sections
        section_entropies = []
        section_size = max(1024, len(file_data) // 10)  # Analyze in 10 sections
        
        for i in range(0, len(file_data), section_size):
            section = file_data[i:i+section_size]
            if section:
                entropy = self._calculate_entropy(section)
                section_entropies.append({
                    'offset': i,
                    'size': len(section),
                    'entropy': entropy
                })
        
        # Analyze entropy distribution
        entropy_analysis = {
            'overall_entropy': overall_entropy,
            'section_entropies': section_entropies,
            'max_entropy': max(s['entropy'] for s in section_entropies) if section_entropies else 0,
            'min_entropy': min(s['entropy'] for s in section_entropies) if section_entropies else 0,
            'entropy_variance': self._calculate_variance([s['entropy'] for s in section_entropies]),
            'high_entropy_sections': [s for s in section_entropies if s['entropy'] > 7.5],
            'assessment': self._assess_entropy(overall_entropy, section_entropies)
        }
        
        return {'entropy': entropy_analysis}
    
    def _calculate_entropy(self, data):
        """
        Calculate Shannon entropy of data
        
        Args:
            data (bytes): Data to analyze
            
        Returns:
            float: Entropy value
        """
        if not data:
            return 0
        
        # Count frequency of each byte
        frequency = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in frequency.values():
            p = count / data_len
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_variance(self, values):
        """Calculate variance of values"""
        if not values:
            return 0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def _assess_entropy(self, overall_entropy, section_entropies):
        """
        Assess entropy characteristics
        
        Args:
            overall_entropy (float): Overall file entropy
            section_entropies (list): Section entropy data
            
        Returns:
            dict: Entropy assessment
        """
        assessment = {
            'likely_packed': False,
            'likely_encrypted': False,
            'suspicious_sections': [],
            'confidence': 'low'
        }
        
        # High overall entropy suggests packing/encryption
        if overall_entropy > 7.5:
            assessment['likely_packed'] = True
            assessment['confidence'] = 'high'
        elif overall_entropy > 7.0:
            assessment['likely_packed'] = True
            assessment['confidence'] = 'medium'
        
        # Check for encryption indicators
        high_entropy_sections = [s for s in section_entropies if s['entropy'] > 7.8]
        if len(high_entropy_sections) > len(section_entropies) * 0.7:
            assessment['likely_encrypted'] = True
        
        # Identify suspicious sections
        for section in section_entropies:
            if section['entropy'] > 7.5:
                assessment['suspicious_sections'].append(section)
        
        return assessment
    
    def _extract_strings(self, file_data, filename, config):
        """
        Extract printable strings from file
        
        Args:
            file_data (bytes): File content
            filename (str): File name
            config (dict): Configuration
            
        Returns:
            dict: String extraction results
        """
        min_length = config.get('min_string_length', 4)
        max_count = config.get('max_strings', 200)
        
        # Extract ASCII strings
        ascii_strings = self._extract_ascii_strings(file_data, min_length, max_count)
        
        # Extract Unicode strings
        unicode_strings = self._extract_unicode_strings(file_data, min_length, max_count // 2)
        
        # Analyze string characteristics
        string_analysis = {
            'ascii_strings': ascii_strings,
            'unicode_strings': unicode_strings,
            'total_strings': len(ascii_strings) + len(unicode_strings),
            'string_statistics': self._analyze_string_statistics(ascii_strings + unicode_strings),
            'interesting_strings': self._find_interesting_strings(ascii_strings + unicode_strings)
        }
        
        return {'strings': string_analysis}
    
    def _extract_ascii_strings(self, data, min_length, max_count):
        """Extract ASCII strings from data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                    if len(strings) >= max_count:
                        break
                current_string = ""
        
        # Add final string if valid
        if len(current_string) >= min_length and len(strings) < max_count:
            strings.append(current_string)
        
        return strings
    
    def _extract_unicode_strings(self, data, min_length, max_count):
        """Extract Unicode strings from data"""
        strings = []
        
        # Try to decode as UTF-16 LE
        try:
            decoded = data.decode('utf-16le', errors='ignore')
            unicode_strings = re.findall(r'[^\x00-\x1f\x7f-\x9f]{%d,}' % min_length, decoded)
            strings.extend(unicode_strings[:max_count])
        except:
            pass
        
        return strings
    
    def _analyze_string_statistics(self, strings):
        """Analyze string statistics"""
        if not strings:
            return {}
        
        lengths = [len(s) for s in strings]
        
        return {
            'total_count': len(strings),
            'average_length': sum(lengths) / len(lengths),
            'max_length': max(lengths),
            'min_length': min(lengths),
            'unique_strings': len(set(strings)),
            'most_common': Counter(strings).most_common(10)
        }
    
    def _find_interesting_strings(self, strings):
        """Find potentially interesting strings"""
        interesting = {
            'file_paths': [],
            'urls': [],
            'emails': [],
            'ip_addresses': [],
            'registry_keys': [],
            'api_calls': [],
            'suspicious_keywords': []
        }
        
        # Define patterns
        patterns = {
            'urls': re.compile(r'https?://[^\s<>"]+', re.IGNORECASE),
            'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_addresses': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'file_paths': re.compile(r'[A-Za-z]:\\[^<>"|?*\n\r]+', re.IGNORECASE),
            'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^<>"|?*\n\r]+', re.IGNORECASE)
        }
        
        # Search for patterns in strings
        for string in strings:
            for pattern_name, pattern in patterns.items():
                matches = pattern.findall(string)
                if matches:
                    interesting[pattern_name].extend(matches)
            
            # Check for API calls
            for api in self.suspicious_patterns['suspicious_apis']:
                if api.lower() in string.lower():
                    interesting['api_calls'].append(string)
            
            # Check for suspicious keywords
            for keyword in self.suspicious_patterns['crypto_indicators']:
                if re.search(keyword, string, re.IGNORECASE):
                    interesting['suspicious_keywords'].append(string)
        
        # Remove duplicates and limit results
        for key in interesting:
            interesting[key] = list(set(interesting[key]))[:20]
        
        return interesting
    
    def _detect_patterns(self, file_data, filename, config):
        """
        Detect suspicious patterns in file
        
        Args:
            file_data (bytes): File content
            filename (str): File name
            config (dict): Configuration
            
        Returns:
            dict: Pattern detection results
        """
        detected_patterns = {}
        
        # Convert to string for pattern matching
        try:
            file_string = file_data.decode('utf-8', errors='ignore')
        except:
            file_string = str(file_data)
        
        # Check each pattern category
        for category, patterns in self.suspicious_patterns.items():
            matches = []
            
            for pattern in patterns:
                if isinstance(pattern, str):
                    # Simple string search
                    if pattern.lower() in file_string.lower():
                        matches.append(pattern)
                else:
                    # Regex pattern
                    try:
                        regex_matches = re.findall(pattern, file_string, re.IGNORECASE)
                        matches.extend(regex_matches)
                    except:
                        pass
            
            if matches:
                detected_patterns[category] = list(set(matches))[:10]  # Limit to 10 matches
        
        # Analyze file header/signature
        file_signature = self._analyze_file_signature(file_data)
        
        return {
            'patterns': detected_patterns,
            'file_signature': file_signature,
            'pattern_statistics': self._calculate_pattern_statistics(detected_patterns)
        }
    
    def _analyze_file_signature(self, file_data):
        """Analyze file signature/header"""
        if len(file_data) < 10:
            return {'type': 'unknown', 'signature': ''}
        
        # Check common file signatures
        header = file_data[:10]
        
        signatures = {
            b'MZ': 'PE Executable',
            b'PK': 'ZIP Archive',
            b'%PDF': 'PDF Document',
            b'7z\xBC\xAF\x27\x1C': '7-Zip Archive',
            b'Rar!': 'RAR Archive',
            b'\x89PNG': 'PNG Image',
            b'JFIF': 'JPEG Image',
            b'GIF8': 'GIF Image'
        }
        
        for sig, file_type in signatures.items():
            if header.startswith(sig):
                return {
                    'type': file_type,
                    'signature': sig.hex(),
                    'confidence': 'high'
                }
        
        return {
            'type': 'unknown',
            'signature': header.hex(),
            'confidence': 'low'
        }
    
    def _calculate_pattern_statistics(self, patterns):
        """Calculate pattern detection statistics"""
        total_patterns = sum(len(matches) for matches in patterns.values())
        
        return {
            'total_patterns': total_patterns,
            'categories_detected': len(patterns),
            'most_common_category': max(patterns.keys(), key=lambda k: len(patterns[k])) if patterns else None,
            'pattern_density': total_patterns / 1000  # patterns per KB (approximate)
        }
    
    def _behavioral_analysis(self, file_data, filename, config):
        """
        Perform behavioral analysis
        
        Args:
            file_data (bytes): File content
            filename (str): File name
            config (dict): Configuration
            
        Returns:
            dict: Behavioral analysis results
        """
        behavioral_indicators = {
            'persistence_mechanisms': [],
            'network_activity': [],
            'file_operations': [],
            'registry_operations': [],
            'process_operations': [],
            'evasion_techniques': []
        }
        
        # Convert to string for analysis
        try:
            file_string = file_data.decode('utf-8', errors='ignore')
        except:
            file_string = str(file_data)
        
        # Check for persistence mechanisms
        persistence_patterns = [
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'CreateService',
            r'OpenService',
            r'StartService'
        ]
        
        for pattern in persistence_patterns:
            if re.search(pattern, file_string, re.IGNORECASE):
                behavioral_indicators['persistence_mechanisms'].append(pattern)
        
        # Check for network activity indicators
        network_patterns = [
            r'InternetOpen',
            r'InternetConnect',
            r'HttpOpenRequest',
            r'socket',
            r'connect',
            r'send',
            r'recv'
        ]
        
        for pattern in network_patterns:
            if re.search(pattern, file_string, re.IGNORECASE):
                behavioral_indicators['network_activity'].append(pattern)
        
        # Check for file operations
        file_patterns = [
            r'CreateFile',
            r'WriteFile',
            r'ReadFile',
            r'DeleteFile',
            r'CopyFile',
            r'MoveFile'
        ]
        
        for pattern in file_patterns:
            if re.search(pattern, file_string, re.IGNORECASE):
                behavioral_indicators['file_operations'].append(pattern)
        
        # Check for evasion techniques
        evasion_patterns = [
            r'VirtualAlloc',
            r'VirtualProtect',
            r'CreateRemoteThread',
            r'WriteProcessMemory',
            r'SetWindowsHookEx',
            r'GetProcAddress'
        ]
        
        for pattern in evasion_patterns:
            if re.search(pattern, file_string, re.IGNORECASE):
                behavioral_indicators['evasion_techniques'].append(pattern)
        
        # Calculate behavioral score
        behavioral_score = self._calculate_behavioral_score(behavioral_indicators)
        
        return {
            'behavioral': {
                'indicators': behavioral_indicators,
                'score': behavioral_score,
                'risk_level': self._assess_behavioral_risk(behavioral_score)
            }
        }
    
    def _calculate_behavioral_score(self, indicators):
        """Calculate behavioral analysis score"""
        score = 0
        
        # Weight different categories
        weights = {
            'persistence_mechanisms': 30,
            'network_activity': 20,
            'file_operations': 10,
            'registry_operations': 15,
            'process_operations': 20,
            'evasion_techniques': 40
        }
        
        for category, weight in weights.items():
            if indicators.get(category):
                score += min(len(indicators[category]) * weight, weight * 2)
        
        return min(score, 100)
    
    def _assess_behavioral_risk(self, score):
        """Assess behavioral risk level"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _analyze_metadata(self, file_data, filename, config):
        """
        Analyze file metadata
        
        Args:
            file_data (bytes): File content
            filename (str): File name
            config (dict): Configuration
            
        Returns:
            dict: Metadata analysis results
        """
        metadata = {
            'filename_analysis': self._analyze_filename(filename),
            'file_size_analysis': self._analyze_file_size(len(file_data)),
            'creation_indicators': self._analyze_creation_indicators(file_data),
            'compilation_indicators': self._analyze_compilation_indicators(file_data)
        }
        
        return {'metadata': metadata}
    
    def _analyze_filename(self, filename):
        """Analyze filename for suspicious characteristics"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar'
        ]
        
        double_extensions = re.findall(r'\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$', filename)
        
        analysis = {
            'suspicious_extension': any(filename.lower().endswith(ext) for ext in suspicious_extensions),
            'double_extension': bool(double_extensions),
            'length': len(filename),
            'has_spaces': ' ' in filename,
            'has_unicode': any(ord(c) > 127 for c in filename),
            'suspicious_keywords': []
        }
        
        # Check for suspicious keywords in filename
        suspicious_keywords = [
            'crack', 'keygen', 'patch', 'hack', 'cheat', 'bot', 'rat', 'trojan',
            'virus', 'malware', 'backdoor', 'rootkit', 'ransomware'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in filename.lower():
                analysis['suspicious_keywords'].append(keyword)
        
        return analysis
    
    def _analyze_file_size(self, file_size):
        """Analyze file size characteristics"""
        return {
            'size_bytes': file_size,
            'size_category': self._categorize_file_size(file_size),
            'suspicious_size': self._is_suspicious_size(file_size)
        }
    
    def _categorize_file_size(self, size):
        """Categorize file size"""
        if size < 1024:
            return 'tiny'
        elif size < 10240:
            return 'small'
        elif size < 102400:
            return 'medium'
        elif size < 1048576:
            return 'large'
        else:
            return 'very_large'
    
    def _is_suspicious_size(self, size):
        """Check if file size is suspicious"""
        # Very small executables might be suspicious
        if size < 1024:
            return True
        
        # Very large files might be suspicious
        if size > 50 * 1024 * 1024:  # 50MB
            return True
        
        return False
    
    def _analyze_creation_indicators(self, file_data):
        """Analyze file creation indicators"""
        indicators = {
            'build_tools': [],
            'compiler_strings': [],
            'development_artifacts': []
        }
        
        # Convert to string for analysis
        try:
            file_string = file_data.decode('utf-8', errors='ignore')
        except:
            file_string = str(file_data)
        
        # Check for build tools
        build_tools = [
            'Microsoft Visual Studio', 'GCC', 'Clang', 'MinGW',
            'Delphi', 'Borland', 'AutoIt', 'NSIS', 'Inno Setup'
        ]
        
        for tool in build_tools:
            if tool in file_string:
                indicators['build_tools'].append(tool)
        
        return indicators
    
    def _analyze_compilation_indicators(self, file_data):
        """Analyze compilation indicators"""
        # This is a simplified analysis
        # In production, use proper PE parsing libraries
        
        indicators = {
            'likely_compiled': False,
            'compiler_version': None,
            'build_timestamp': None,
            'debug_info': False
        }
        
        # Check for PE header
        if len(file_data) > 64 and file_data[:2] == b'MZ':
            indicators['likely_compiled'] = True
            
            # Look for debug information
            if b'debug' in file_data.lower() or b'pdb' in file_data.lower():
                indicators['debug_info'] = True
        
        return indicators
    
    def _assess_threat(self, results, config):
        """
        Assess overall threat level based on analysis results
        
        Args:
            results (dict): Analysis results
            config (dict): Configuration
            
        Returns:
            dict: Threat assessment
        """
        threat_score = 0
        threat_reasons = []
        
        # Entropy analysis
        if 'entropy' in results:
            entropy_data = results['entropy']
            if entropy_data.get('overall_entropy', 0) > 7.5:
                threat_score += 30
                threat_reasons.append("High entropy detected - possible encryption/packing")
            elif entropy_data.get('overall_entropy', 0) > 7.0:
                threat_score += 15
                threat_reasons.append("Moderate entropy detected")
        
        # Pattern detection
        if 'patterns' in results:
            pattern_data = results['patterns']
            if pattern_data.get('suspicious_apis'):
                threat_score += 25
                threat_reasons.append("Suspicious API calls detected")
            
            if pattern_data.get('crypto_indicators'):
                threat_score += 20
                threat_reasons.append("Cryptocurrency-related strings found")
            
            if pattern_data.get('network_indicators'):
                threat_score += 15
                threat_reasons.append("Network activity indicators found")
        
        # Behavioral analysis
        if 'behavioral' in results:
            behavioral_score = results['behavioral'].get('score', 0)
            if behavioral_score >= 60:
                threat_score += 30
                threat_reasons.append("High behavioral risk score")
            elif behavioral_score >= 40:
                threat_score += 20
                threat_reasons.append("Medium behavioral risk score")
        
        # String analysis
        if 'strings' in results:
            string_data = results['strings']
            interesting = string_data.get('interesting_strings', {})
            
            if interesting.get('suspicious_keywords'):
                threat_score += 15
                threat_reasons.append("Suspicious keywords in strings")
            
            if interesting.get('registry_keys'):
                threat_score += 10
                threat_reasons.append("Registry operations detected")
        
        # Metadata analysis
        if 'metadata' in results:
            metadata = results['metadata']
            filename_analysis = metadata.get('filename_analysis', {})
            
            if filename_analysis.get('suspicious_extension'):
                threat_score += 10
                threat_reasons.append("Suspicious file extension")
            
            if filename_analysis.get('double_extension'):
                threat_score += 15
                threat_reasons.append("Double file extension detected")
            
            if filename_analysis.get('suspicious_keywords'):
                threat_score += 10
                threat_reasons.append("Suspicious keywords in filename")
        
        # Determine threat level
        if threat_score >= 80:
            level = 'CRITICAL'
        elif threat_score >= 60:
            level = 'HIGH'
        elif threat_score >= 40:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'level': level,
            'score': min(threat_score, 100),
            'reasons': threat_reasons,
            'confidence': self._calculate_confidence(results),
            'recommendation': self._get_recommendation(level, threat_score)
        }
    
    def _calculate_confidence(self, results):
        """Calculate confidence level of the analysis"""
        factors = 0
        
        # More analysis modules increase confidence
        if 'hashes' in results:
            factors += 1
        if 'entropy' in results:
            factors += 1
        if 'strings' in results:
            factors += 1
        if 'patterns' in results:
            factors += 1
        if 'behavioral' in results:
            factors += 1
        
        if factors >= 4:
            return 'high'
        elif factors >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _get_recommendation(self, level, score):
        """Get recommendation based on threat level"""
        recommendations = {
            'CRITICAL': "Do not execute this file. It shows multiple indicators of malicious behavior. Consider submitting to security vendors for analysis.",
            'HIGH': "Exercise extreme caution. This file exhibits suspicious characteristics and should be analyzed in a controlled environment.",
            'MEDIUM': "This file shows some suspicious indicators. Verify its source and consider additional analysis before use.",
            'LOW': "File appears to be relatively safe, but always exercise caution with unknown files."
        }
        
        return recommendations.get(level, "Unable to determine safety level.")
