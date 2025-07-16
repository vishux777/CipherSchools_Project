"""
Analysis Engine for MalwareShield Pro
Comprehensive file analysis with entropy, strings, and pattern detection

Built with 🛡️ by [Vishwas]
"""

import re
import math
import string
from collections import Counter
from typing import Dict, List, Any, Optional

class AnalysisEngine:
    """Main analysis engine for malware detection"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'password', 'keylog', 'backdoor', 'trojan', 'virus', 'malware',
            'exploit', 'payload', 'shell', 'rootkit', 'botnet', 'cryptocurrency',
            'bitcoin', 'wallet', 'mining', 'cmd.exe', 'powershell', 'download',
            'execute', 'inject', 'bypass', 'disable', 'antivirus', 'firewall',
            'registry', 'process', 'thread', 'memory', 'heap', 'stack',
            'debug', 'trace', 'hook', 'patch', 'obfuscate', 'encrypt'
        ]
        
        self.file_signatures = {
            b'\x4D\x5A': 'PE/DOS Executable',
            b'\x50\x4B\x03\x04': 'ZIP Archive',
            b'\x50\x4B\x05\x06': 'ZIP Archive (empty)',
            b'\x50\x4B\x07\x08': 'ZIP Archive (spanned)',
            b'\x25\x50\x44\x46': 'PDF Document',
            b'\xD0\xCF\x11\xE0': 'Microsoft Office Document',
            b'\x89\x50\x4E\x47': 'PNG Image',
            b'\xFF\xD8\xFF': 'JPEG Image',
            b'\x47\x49\x46\x38': 'GIF Image',
            b'\x1F\x8B\x08': 'GZIP Archive',
            b'\x42\x5A\x68': 'BZIP2 Archive',
            b'\x37\x7A\xBC\xAF': '7-Zip Archive'
        }
    
    def analyze_file(self, file_data: bytes, filename: str, config: Dict) -> Dict[str, Any]:
        """
        Perform comprehensive file analysis
        
        Args:
            file_data: Raw file bytes
            filename: Original filename
            config: Analysis configuration
            
        Returns:
            Dict containing analysis results
        """
        results = {
            'filename': filename,
            'file_size': len(file_data),
            'file_type': self._detect_file_type(file_data),
            'entropy': self._calculate_entropy(file_data),
            'strings': [],
            'patterns': {},
            'suspicious_indicators': [],
            'risk_factors': []
        }
        
        try:
            # Extract strings if enabled
            if config.get('string_analysis', True):
                results['strings'] = self._extract_strings(
                    file_data, 
                    config.get('min_string_length', 4),
                    config.get('max_strings', 1000)
                )
            
            # Analyze patterns if enabled
            if config.get('pattern_analysis', True):
                results['patterns'] = self._analyze_patterns(results['strings'])
            
            # Check for suspicious indicators
            results['suspicious_indicators'] = self._find_suspicious_indicators(
                file_data, results['strings']
            )
            
            # Calculate risk factors
            results['risk_factors'] = self._calculate_risk_factors(results)
            
        except Exception as e:
            results['error'] = f"Analysis error: {str(e)}"
        
        return results
    
    def _detect_file_type(self, file_data: bytes) -> str:
        """Detect file type based on magic bytes"""
        if not file_data:
            return "Unknown"
        
        for signature, file_type in self.file_signatures.items():
            if file_data.startswith(signature):
                return file_type
        
        return "Unknown"
    
    def _calculate_entropy(self, file_data: bytes) -> float:
        """Calculate Shannon entropy of file data"""
        if not file_data:
            return 0.0
        
        try:
            # Count byte frequencies
            byte_counts = Counter(file_data)
            total_bytes = len(file_data)
            
            # Calculate entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
            
            return round(entropy, 3)
        except:
            return 0.0
    
    def _extract_strings(self, file_data: bytes, min_length: int = 4, max_strings: int = 1000) -> List[str]:
        """Extract readable strings from binary data"""
        try:
            # ASCII strings
            ascii_strings = re.findall(
                rb'[!-~]{' + str(min_length).encode() + rb',}',
                file_data
            )
            
            # Unicode strings (basic)
            unicode_strings = re.findall(
                rb'(?:[!-~]\x00){' + str(min_length).encode() + rb',}',
                file_data
            )
            
            # Combine and decode
            all_strings = []
            
            # Process ASCII strings
            for s in ascii_strings:
                try:
                    decoded = s.decode('utf-8', errors='ignore')
                    if decoded and len(decoded) >= min_length:
                        all_strings.append(decoded)
                except:
                    continue
            
            # Process Unicode strings
            for s in unicode_strings:
                try:
                    decoded = s.decode('utf-16le', errors='ignore')
                    if decoded and len(decoded) >= min_length:
                        all_strings.append(decoded)
                except:
                    continue
            
            # Remove duplicates and limit
            unique_strings = list(set(all_strings))
            return unique_strings[:max_strings]
            
        except Exception as e:
            return []
    
    def _analyze_patterns(self, strings: List[str]) -> Dict[str, List[str]]:
        """Analyze patterns in extracted strings"""
        patterns = {
            'urls': [],
            'ips': [],
            'emails': [],
            'domains': [],
            'file_paths': [],
            'registry_keys': [],
            'suspicious_keywords': []
        }
        
        # Pattern definitions
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        domain_pattern = re.compile(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b')
        path_pattern = re.compile(r'[A-Za-z]:\\[^<>:"|?*\n\r]*', re.IGNORECASE)
        registry_pattern = re.compile(r'HKEY_[A-Z_]+\\[^<>:"|?*\n\r]*', re.IGNORECASE)
        
        try:
            for string in strings:
                # URLs
                urls = url_pattern.findall(string)
                patterns['urls'].extend(urls)
                
                # IP addresses
                ips = ip_pattern.findall(string)
                patterns['ips'].extend(ips)
                
                # Email addresses
                emails = email_pattern.findall(string)
                patterns['emails'].extend(emails)
                
                # Domains
                domains = domain_pattern.findall(string)
                patterns['domains'].extend(domains)
                
                # File paths
                paths = path_pattern.findall(string)
                patterns['file_paths'].extend(paths)
                
                # Registry keys
                registry_keys = registry_pattern.findall(string)
                patterns['registry_keys'].extend(registry_keys)
                
                # Suspicious keywords
                for keyword in self.suspicious_keywords:
                    if keyword.lower() in string.lower():
                        patterns['suspicious_keywords'].append(keyword)
            
            # Remove duplicates and limit results
            for key in patterns:
                patterns[key] = list(set(patterns[key]))[:50]  # Limit to 50 per category
            
            return patterns
        except:
            return patterns
    
    def _find_suspicious_indicators(self, file_data: bytes, strings: List[str]) -> List[str]:
        """Find suspicious indicators in file"""
        indicators = []
        
        try:
            # Check for packed/compressed content (high entropy)
            entropy = self._calculate_entropy(file_data)
            if entropy > 7.0:
                indicators.append("High entropy - possibly packed/encrypted")
            
            # Check for suspicious API calls
            suspicious_apis = [
                'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc', 
                'LoadLibrary', 'GetProcAddress', 'RegCreateKey', 'RegSetValue',
                'CreateFile', 'WriteFile', 'CreateThread', 'OpenProcess',
                'SetWindowsHook', 'FindWindow', 'GetWindow', 'MessageBox'
            ]
            
            for api in suspicious_apis:
                if any(api.lower() in s.lower() for s in strings):
                    indicators.append(f"Suspicious API call: {api}")
            
            # Check for network indicators
            network_keywords = ['socket', 'connect', 'send', 'recv', 'http', 'tcp', 'udp']
            for keyword in network_keywords:
                if any(keyword.lower() in s.lower() for s in strings):
                    indicators.append(f"Network activity indicator: {keyword}")
                    break
            
            # Check for crypto indicators
            crypto_keywords = ['encrypt', 'decrypt', 'cipher', 'key', 'aes', 'rsa', 'md5', 'sha']
            for keyword in crypto_keywords:
                if any(keyword.lower() in s.lower() for s in strings):
                    indicators.append(f"Cryptographic indicator: {keyword}")
                    break
            
            # Check for persistence mechanisms
            persistence_keywords = ['autorun', 'startup', 'service', 'task', 'scheduled']
            for keyword in persistence_keywords:
                if any(keyword.lower() in s.lower() for s in strings):
                    indicators.append(f"Persistence mechanism: {keyword}")
                    break
            
            return indicators
        except:
            return indicators
    
    def _calculate_risk_factors(self, results: Dict) -> List[str]:
        """Calculate risk factors based on analysis results"""
        risk_factors = []
        
        try:
            # High entropy risk
            if results.get('entropy', 0) > 6.5:
                risk_factors.append("High entropy content")
            
            # Suspicious patterns
            patterns = results.get('patterns', {})
            if patterns.get('urls'):
                risk_factors.append(f"Contains {len(patterns['urls'])} URLs")
            if patterns.get('ips'):
                risk_factors.append(f"Contains {len(patterns['ips'])} IP addresses")
            if patterns.get('suspicious_keywords'):
                risk_factors.append(f"Contains {len(patterns['suspicious_keywords'])} suspicious keywords")
            
            # File size factors
            file_size = results.get('file_size', 0)
            if file_size > 10 * 1024 * 1024:  # > 10MB
                risk_factors.append("Large file size")
            elif file_size < 1024:  # < 1KB
                risk_factors.append("Very small file size")
            
            # Suspicious indicators
            indicators = results.get('suspicious_indicators', [])
            if len(indicators) > 3:
                risk_factors.append(f"Multiple suspicious indicators ({len(indicators)})")
            
            return risk_factors
        except:
            return risk_factors
