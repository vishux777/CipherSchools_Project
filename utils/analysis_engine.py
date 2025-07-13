"""
Analysis Engine Module

Provides comprehensive local file analysis capabilities including entropy analysis,
pattern detection, string extraction, and threat assessment.
"""

import re
import math
import string
import hashlib
from collections import Counter
from typing import Dict, List, Any, Tuple

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

class AnalysisEngine:
    """Core analysis engine for local file scanning and threat detection"""
    
    def __init__(self):
        """Initialize the analysis engine"""
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.malware_signatures = self._load_malware_signatures()
    
    def analyze_file(self, file_data: bytes, filename: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive file analysis
        
        Args:
            file_data: Binary file data
            filename: Original filename
            config: Analysis configuration options
            
        Returns:
            dict: Complete analysis results
        """
        if config is None:
            config = self._get_default_config()
        
        try:
            results = {
                'filename': filename,
                'file_size': len(file_data),
                'file_type': self._detect_file_type(file_data, filename),
                'hashes': self._calculate_hashes(file_data),
                'entropy': self._calculate_entropy(file_data),
                'strings': self._extract_strings(file_data, config),
                'patterns': self._detect_patterns(file_data, config),
                'signatures': self._check_signatures(file_data),
                'metadata': self._extract_metadata(file_data, filename),
                'suspicious_indicators': []
            }
            
            # Analyze for suspicious indicators
            results['suspicious_indicators'] = self._find_suspicious_indicators(results)
            
            return results
            
        except Exception as e:
            return {
                'error': f"Analysis failed: {str(e)}",
                'filename': filename
            }
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default analysis configuration
        
        Returns:
            dict: Default configuration
        """
        return {
            'min_string_length': 4,
            'max_strings': 1000,
            'deep_scan': True,
            'pattern_analysis': True,
            'entropy_threshold': 7.5
        }
    
    def _detect_file_type(self, file_data: bytes, filename: str) -> str:
        """Detect file type using multiple methods
        
        Args:
            file_data: Binary file data
            filename: Original filename
            
        Returns:
            str: Detected file type
        """
        try:
            # Try to use python-magic for file type detection
            if MAGIC_AVAILABLE:
                try:
                    mime_type = magic.from_buffer(file_data, mime=True)
                    return mime_type
                except Exception:
                    pass
            
            # Fallback to extension-based detection
            if '.' in filename:
                extension = filename.split('.')[-1].lower()
                
                type_map = {
                    'exe': 'application/x-executable',
                    'dll': 'application/x-library',
                    'pdf': 'application/pdf',
                    'doc': 'application/msword',
                    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'zip': 'application/zip',
                    'rar': 'application/x-rar',
                    'txt': 'text/plain',
                    'py': 'text/x-python',
                    'js': 'text/javascript',
                    'html': 'text/html',
                    'jpg': 'image/jpeg',
                    'png': 'image/png',
                    'gif': 'image/gif'
                }
                
                return type_map.get(extension, 'application/octet-stream')
            
            # Magic number detection
            if file_data.startswith(b'MZ'):
                return 'application/x-executable'
            elif file_data.startswith(b'%PDF'):
                return 'application/pdf'
            elif file_data.startswith(b'PK'):
                return 'application/zip'
            elif file_data.startswith(b'\x7fELF'):
                return 'application/x-executable'
            
            return 'application/octet-stream'
            
        except Exception:
            return 'unknown'
    
    def _calculate_hashes(self, file_data: bytes) -> Dict[str, str]:
        """Calculate multiple hashes for the file
        
        Args:
            file_data: Binary file data
            
        Returns:
            dict: Hash values
        """
        return {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'sha512': hashlib.sha512(file_data).hexdigest()
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data
        
        Args:
            data: Binary data
            
        Returns:
            float: Entropy value
        """
        if not data:
            return 0.0
        
        # Count frequency of each byte
        frequency = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in frequency.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _extract_strings(self, file_data: bytes, config: Dict[str, Any]) -> List[str]:
        """Extract printable strings from file data
        
        Args:
            file_data: Binary file data
            config: Analysis configuration
            
        Returns:
            list: Extracted strings
        """
        min_length = config.get('min_string_length', 4)
        max_strings = config.get('max_strings', 1000)
        
        strings = []
        current_string = ""
        
        for byte in file_data:
            if byte < 128:  # ASCII range
                char = chr(byte)
                if char in string.printable and char not in '\t\n\r\x0b\x0c':
                    current_string += char
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                        if len(strings) >= max_strings:
                            break
                    current_string = ""
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                    if len(strings) >= max_strings:
                        break
                current_string = ""
        
        # Add final string if valid
        if len(current_string) >= min_length and len(strings) < max_strings:
            strings.append(current_string)
        
        return strings
    
    def _detect_patterns(self, file_data: bytes, config: Dict[str, Any]) -> Dict[str, List[str]]:
        """Detect suspicious patterns in file data
        
        Args:
            file_data: Binary file data
            config: Analysis configuration
            
        Returns:
            dict: Detected patterns by category
        """
        if not config.get('pattern_analysis', True):
            return {}
        
        # Convert to string for pattern matching
        try:
            file_string = file_data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            file_string = str(file_data)
        
        detected_patterns = {}
        
        for category, patterns in self.suspicious_patterns.items():
            matches = []
            for pattern_name, pattern in patterns.items():
                found = pattern.findall(file_string)
                if found:
                    matches.extend(found)
            
            if matches:
                # Remove duplicates and limit results
                detected_patterns[category] = list(set(matches))[:50]
        
        return detected_patterns
    
    def _check_signatures(self, file_data: bytes) -> Dict[str, Any]:
        """Check for known malware signatures
        
        Args:
            file_data: Binary file data
            
        Returns:
            dict: Signature analysis results
        """
        signature_matches = []
        
        for signature_name, signature_data in self.malware_signatures.items():
            pattern = signature_data['pattern']
            if isinstance(pattern, bytes):
                if pattern in file_data:
                    signature_matches.append({
                        'name': signature_name,
                        'type': signature_data.get('type', 'unknown'),
                        'severity': signature_data.get('severity', 'medium'),
                        'description': signature_data.get('description', 'Known malware signature')
                    })
            elif isinstance(pattern, str):
                try:
                    regex_pattern = re.compile(pattern.encode(), re.IGNORECASE)
                    if regex_pattern.search(file_data):
                        signature_matches.append({
                            'name': signature_name,
                            'type': signature_data.get('type', 'unknown'),
                            'severity': signature_data.get('severity', 'medium'),
                            'description': signature_data.get('description', 'Known malware signature')
                        })
                except re.error:
                    continue
        
        return {
            'total_matches': len(signature_matches),
            'matches': signature_matches
        }
    
    def _extract_metadata(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Extract file metadata
        
        Args:
            file_data: Binary file data
            filename: Original filename
            
        Returns:
            dict: File metadata
        """
        metadata = {
            'size': len(file_data),
            'extension': filename.split('.')[-1] if '.' in filename else '',
            'has_overlay': False,
            'sections': []
        }
        
        # PE file analysis
        if file_data.startswith(b'MZ'):
            metadata.update(self._analyze_pe_metadata(file_data))
        
        return metadata
    
    def _analyze_pe_metadata(self, file_data: bytes) -> Dict[str, Any]:
        """Analyze PE file metadata
        
        Args:
            file_data: PE file data
            
        Returns:
            dict: PE metadata
        """
        try:
            # Basic PE header analysis
            if len(file_data) < 64:
                return {'error': 'File too small for PE analysis'}
            
            # Check for PE signature
            pe_offset = int.from_bytes(file_data[60:64], 'little')
            if pe_offset >= len(file_data) - 4:
                return {'error': 'Invalid PE offset'}
            
            pe_signature = file_data[pe_offset:pe_offset+4]
            if pe_signature != b'PE\x00\x00':
                return {'error': 'Invalid PE signature'}
            
            return {
                'is_pe': True,
                'pe_offset': pe_offset,
                'architecture': 'x86' if file_data[pe_offset+4:pe_offset+6] == b'\x4c\x01' else 'x64'
            }
            
        except Exception as e:
            return {'error': f'PE analysis failed: {str(e)}'}
    
    def _find_suspicious_indicators(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find suspicious indicators based on analysis results
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            list: Suspicious indicators found
        """
        indicators = []
        
        # High entropy check
        entropy = analysis_results.get('entropy', 0)
        if entropy > 7.5:
            indicators.append({
                'type': 'high_entropy',
                'severity': 'medium',
                'description': f'High entropy detected ({entropy:.2f}) - possible encryption/packing',
                'value': entropy
            })
        
        # Suspicious patterns
        patterns = analysis_results.get('patterns', {})
        for category, matches in patterns.items():
            if matches:
                indicators.append({
                    'type': 'suspicious_pattern',
                    'severity': 'medium',
                    'description': f'Suspicious {category} patterns detected',
                    'value': len(matches),
                    'category': category
                })
        
        # Signature matches
        signatures = analysis_results.get('signatures', {})
        signature_matches = signatures.get('matches', [])
        for match in signature_matches:
            indicators.append({
                'type': 'malware_signature',
                'severity': match.get('severity', 'high'),
                'description': f"Known malware signature: {match['name']}",
                'value': match['name']
            })
        
        # Large file size
        file_size = analysis_results.get('file_size', 0)
        if file_size > 50 * 1024 * 1024:  # 50MB
            indicators.append({
                'type': 'large_file',
                'severity': 'low',
                'description': f'Large file size ({file_size} bytes) - unusual for malware',
                'value': file_size
            })
        
        return indicators
    
    def _load_suspicious_patterns(self) -> Dict[str, Dict[str, re.Pattern]]:
        """Load suspicious pattern definitions
        
        Returns:
            dict: Suspicious patterns by category
        """
        patterns = {
            'network': {
                'urls': re.compile(r'https?://[^\s<>"]+', re.IGNORECASE),
                'ips': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
                'domains': re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'),
                'email_addresses': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            },
            'system': {
                'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^\\]+', re.IGNORECASE),
                'file_paths': re.compile(r'[A-Za-z]:\\[^\\]+(?:\\[^\\]+)*', re.IGNORECASE),
                'windows_apis': re.compile(r'\b(CreateFile|WriteFile|RegCreateKey|RegSetValue|GetProcAddress|LoadLibrary|VirtualAlloc|CreateProcess|ShellExecute)\b', re.IGNORECASE),
                'process_names': re.compile(r'\b(cmd\.exe|powershell\.exe|rundll32\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe)\b', re.IGNORECASE)
            },
            'crypto': {
                'bitcoin_addresses': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
                'ethereum_addresses': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
                'crypto_keywords': re.compile(r'\b(bitcoin|btc|wallet|private[_\s]?key|encryption|decrypt|cipher|ransom|unlock)\b', re.IGNORECASE)
            },
            'malware': {
                'packer_indicators': re.compile(r'\b(upx|pex|aspack|fsg|mpress)\b', re.IGNORECASE),
                'steganography': re.compile(r'\b(steghide|stegsolve|outguess|jphide)\b', re.IGNORECASE),
                'persistence': re.compile(r'\b(startup|autorun|scheduled task|service|registry run)\b', re.IGNORECASE)
            }
        }
        
        return patterns
    
    def _load_malware_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load malware signature definitions
        
        Returns:
            dict: Malware signatures
        """
        signatures = {
            'generic_trojan_1': {
                'pattern': b'\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff',
                'type': 'trojan',
                'severity': 'high',
                'description': 'Generic trojan signature pattern'
            },
            'wannacry_string': {
                'pattern': r'WannaCry|Wana\s*Decrypt|\.wncryt',
                'type': 'ransomware',
                'severity': 'critical',
                'description': 'WannaCry ransomware indicators'
            },
            'emotet_string': {
                'pattern': r'emotet|heodo|feodo',
                'type': 'trojan',
                'severity': 'high',
                'description': 'Emotet trojan indicators'
            }
        }
        
        return signatures
