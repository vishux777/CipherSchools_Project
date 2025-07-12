"""
Analysis Engine Module

Advanced file analysis engine with comprehensive static analysis capabilities
including entropy calculation, string extraction, pattern detection, and heuristic analysis.
"""

import hashlib
import math
import re
import string
import struct
import os
from collections import Counter
from datetime import datetime
import json

class AnalysisEngine:
    """
    Comprehensive file analysis engine for malware detection
    """
    
    def __init__(self):
        """Initialize the analysis engine with pattern databases"""
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.file_signatures = self._load_file_signatures()
        self.api_patterns = self._load_api_patterns()
        
    def _load_suspicious_patterns(self):
        """Load suspicious pattern definitions"""
        return {
            'urls': re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE),
            'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_addresses': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'bitcoin_addresses': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'ethereum_addresses': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'file_paths': re.compile(r'[A-Za-z]:\\\\[^\\]+(?:\\\\[^\\]+)*', re.IGNORECASE),
            'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^\\]+', re.IGNORECASE),
            'base64_data': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex_data': re.compile(r'[0-9a-fA-F]{32,}'),
            'phone_numbers': re.compile(r'\+?[1-9]\d{1,14}'),
            'credit_cards': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'social_security': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),
            'passwords': re.compile(r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*[\'""]?([^\s\'"";,]+)', re.IGNORECASE)
        }
    
    def _load_file_signatures(self):
        """Load file signature patterns for identification"""
        return {
            'pe_executable': [b'\x4d\x5a', b'PE\x00\x00'],  # MZ header, PE signature
            'elf_executable': [b'\x7fELF'],
            'java_class': [b'\xca\xfe\xba\xbe'],
            'pdf': [b'%PDF'],
            'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
            'rar': [b'Rar!\x1a\x07\x00'],
            'gzip': [b'\x1f\x8b'],
            'bzip2': [b'BZ'],
            '7zip': [b'7z\xbc\xaf\x27\x1c'],
            'tar': [b'ustar'],
            'dmg': [b'koly'],
            'iso': [b'CD001'],
            'script_batch': [b'@echo off', b'rem ', b'REM '],
            'script_powershell': [b'powershell', b'PowerShell'],
            'script_vbs': [b'WScript', b'VBScript'],
            'script_js': [b'<script', b'javascript:'],
            'office_doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],  # OLE2 signature
            'rtf': [b'{\\rtf'],
            'xml': [b'<?xml'],
            'html': [b'<html', b'<HTML'],
            'macho': [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']
        }
    
    def _load_api_patterns(self):
        """Load suspicious API call patterns"""
        return {
            'file_operations': re.compile(r'\b(CreateFile|WriteFile|ReadFile|DeleteFile|CopyFile|MoveFile)\w*\b', re.IGNORECASE),
            'registry_operations': re.compile(r'\b(RegCreateKey|RegSetValue|RegDeleteKey|RegOpenKey|RegQueryValue)\w*\b', re.IGNORECASE),
            'process_operations': re.compile(r'\b(CreateProcess|TerminateProcess|OpenProcess|GetCurrentProcess)\w*\b', re.IGNORECASE),
            'memory_operations': re.compile(r'\b(VirtualAlloc|VirtualFree|VirtualProtect|HeapAlloc|HeapFree)\w*\b', re.IGNORECASE),
            'network_operations': re.compile(r'\b(socket|connect|send|recv|WSAStartup|InternetOpen|InternetConnect)\w*\b', re.IGNORECASE),
            'crypto_operations': re.compile(r'\b(CryptAcquireContext|CryptCreateHash|CryptEncrypt|CryptDecrypt)\w*\b', re.IGNORECASE),
            'service_operations': re.compile(r'\b(CreateService|StartService|ControlService|DeleteService)\w*\b', re.IGNORECASE),
            'debug_operations': re.compile(r'\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)\w*\b', re.IGNORECASE),
            'injection_operations': re.compile(r'\b(WriteProcessMemory|ReadProcessMemory|SetWindowsHook|LoadLibrary|GetProcAddress)\w*\b', re.IGNORECASE),
            'persistence_operations': re.compile(r'\b(SetWindowsHook|RegisterHotKey|SetTimer|WinExec|ShellExecute)\w*\b', re.IGNORECASE)
        }
    
    def analyze_file(self, file_data, filename, config=None):
        """
        Perform comprehensive file analysis
        
        Args:
            file_data (bytes): File content as bytes
            filename (str): Original filename
            config (dict): Analysis configuration options
            
        Returns:
            dict: Comprehensive analysis results
        """
        if config is None:
            config = {
                'deep_analysis': True,
                'extract_strings': True,
                'pattern_detection': True,
                'entropy_analysis': True,
                'signature_analysis': True,
                'min_string_length': 4,
                'max_strings': 500
            }
        
        # Initialize results structure
        results = {
            'filename': filename,
            'file_size': len(file_data),
            'analysis_time': datetime.now().isoformat(),
            'file_info': {},
            'hashes': {},
            'entropy': {},
            'strings': {},
            'patterns': {},
            'file_signature': {},
            'suspicious_indicators': [],
            'threat_assessment': {}
        }
        
        try:
            # Basic file information
            results['file_info'] = self._analyze_file_info(file_data, filename)
            
            # Calculate hashes
            results['hashes'] = self._calculate_hashes(file_data)
            
            # Entropy analysis
            if config.get('entropy_analysis', True):
                results['entropy'] = self._analyze_entropy(file_data)
            
            # String extraction
            if config.get('extract_strings', True):
                results['strings'] = self._extract_strings(
                    file_data, 
                    config.get('min_string_length', 4),
                    config.get('max_strings', 500)
                )
            
            # Pattern detection
            if config.get('pattern_detection', True):
                results['patterns'] = self._detect_patterns(file_data, results['strings'])
            
            # File signature analysis
            if config.get('signature_analysis', True):
                results['file_signature'] = self._analyze_file_signature(file_data)
            
            # Deep analysis
            if config.get('deep_analysis', True):
                results['suspicious_indicators'] = self._find_suspicious_indicators(results)
            
            # Overall threat assessment
            results['threat_assessment'] = self._assess_threat_level(results)
            
        except Exception as e:
            results['error'] = f"Analysis failed: {str(e)}"
            results['status'] = 'error'
        
        return results
    
    def _analyze_file_info(self, file_data, filename):
        """Extract basic file information"""
        file_info = {
            'original_name': filename,
            'size_bytes': len(file_data),
            'size_human': self._format_file_size(len(file_data)),
            'extension': os.path.splitext(filename)[1].lower() if '.' in filename else '',
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Try to determine file type from content
        detected_type = self._detect_file_type(file_data)
        if detected_type:
            file_info['detected_type'] = detected_type
        
        return file_info
    
    def _calculate_hashes(self, file_data):
        """Calculate multiple hash types for the file"""
        hashes = {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'sha512': hashlib.sha512(file_data).hexdigest()
        }
        
        # Add SSDEEP if available
        try:
            import ssdeep
            hashes['ssdeep'] = ssdeep.hash(file_data)
        except ImportError:
            pass
        
        return hashes
    
    def _analyze_entropy(self, file_data):
        """Perform comprehensive entropy analysis"""
        if not file_data:
            return {'overall_entropy': 0, 'sections': []}
        
        # Calculate overall entropy
        overall_entropy = self._calculate_entropy(file_data)
        
        # Calculate entropy for sections
        section_size = 1024  # 1KB sections
        sections = []
        
        for i in range(0, len(file_data), section_size):
            section_data = file_data[i:i+section_size]
            if len(section_data) > 0:
                section_entropy = self._calculate_entropy(section_data)
                sections.append({
                    'offset': i,
                    'size': len(section_data),
                    'entropy': section_entropy
                })
        
        # Find high entropy sections
        high_entropy_sections = [s for s in sections if s['entropy'] > 7.5]
        
        return {
            'overall_entropy': overall_entropy,
            'section_count': len(sections),
            'high_entropy_sections': len(high_entropy_sections),
            'max_section_entropy': max([s['entropy'] for s in sections]) if sections else 0,
            'avg_section_entropy': sum([s['entropy'] for s in sections]) / len(sections) if sections else 0,
            'sections': sections[:50]  # Limit to first 50 sections for performance
        }
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
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
    
    def _extract_strings(self, file_data, min_length=4, max_count=500):
        """Extract ASCII and Unicode strings from file data"""
        ascii_strings = []
        unicode_strings = []
        
        # Extract ASCII strings
        current_string = ""
        for byte in file_data:
            char = chr(byte) if 32 <= byte <= 126 else None
            if char:
                current_string += char
            else:
                if len(current_string) >= min_length:
                    ascii_strings.append(current_string)
                    if len(ascii_strings) >= max_count // 2:
                        break
                current_string = ""
        
        # Add final ASCII string if valid
        if len(current_string) >= min_length and len(ascii_strings) < max_count // 2:
            ascii_strings.append(current_string)
        
        # Extract Unicode strings (UTF-16)
        try:
            i = 0
            while i < len(file_data) - 1 and len(unicode_strings) < max_count // 2:
                try:
                    # Try to decode as UTF-16LE
                    char_bytes = file_data[i:i+2]
                    if len(char_bytes) == 2:
                        char = char_bytes.decode('utf-16le')
                        if char.isprintable() and char not in '\r\n\t':
                            # Start of potential string
                            j = i + 2
                            unicode_string = char
                            while j < len(file_data) - 1:
                                try:
                                    next_char_bytes = file_data[j:j+2]
                                    if len(next_char_bytes) == 2:
                                        next_char = next_char_bytes.decode('utf-16le')
                                        if next_char.isprintable() and next_char not in '\r\n\t':
                                            unicode_string += next_char
                                            j += 2
                                        else:
                                            break
                                    else:
                                        break
                                except:
                                    break
                            
                            if len(unicode_string) >= min_length:
                                unicode_strings.append(unicode_string)
                            
                            i = j
                        else:
                            i += 1
                    else:
                        i += 1
                except:
                    i += 1
        except:
            pass
        
        return {
            'ascii_strings': ascii_strings,
            'unicode_strings': unicode_strings,
            'total_ascii': len(ascii_strings),
            'total_unicode': len(unicode_strings),
            'combined': ascii_strings + unicode_strings
        }
    
    def _detect_patterns(self, file_data, strings_data):
        """Detect suspicious patterns in file content and strings"""
        patterns = {}
        
        # Get all strings for pattern matching
        all_strings = []
        if isinstance(strings_data, dict):
            all_strings.extend(strings_data.get('ascii_strings', []))
            all_strings.extend(strings_data.get('unicode_strings', []))
        elif isinstance(strings_data, list):
            all_strings = strings_data
        
        combined_text = ' '.join(all_strings)
        
        # Apply pattern detection
        for pattern_name, pattern in self.suspicious_patterns.items():
            matches = pattern.findall(combined_text)
            if matches:
                patterns[pattern_name] = list(set(matches))  # Remove duplicates
        
        # Apply API pattern detection
        for api_category, pattern in self.api_patterns.items():
            matches = pattern.findall(combined_text)
            if matches:
                patterns[f'api_{api_category}'] = list(set(matches))
        
        return patterns
    
    def _analyze_file_signature(self, file_data):
        """Analyze file signature and identify file type"""
        if len(file_data) < 10:
            return {'detected_types': [], 'confidence': 'low'}
        
        detected_types = []
        
        # Check first 512 bytes for signatures
        header = file_data[:512]
        
        for file_type, signatures in self.file_signatures.items():
            for signature in signatures:
                if signature in header:
                    detected_types.append(file_type)
                    break
        
        # Additional specific checks
        if file_data.startswith(b'\x4d\x5a'):  # MZ header
            # Look for PE signature
            if b'PE\x00\x00' in file_data[:1024]:
                if 'pe_executable' not in detected_types:
                    detected_types.append('pe_executable')
        
        confidence = 'high' if detected_types else 'low'
        
        return {
            'detected_types': detected_types,
            'confidence': confidence,
            'primary_type': detected_types[0] if detected_types else 'unknown'
        }
    
    def _detect_file_type(self, file_data):
        """Simple file type detection based on content"""
        if len(file_data) < 4:
            return 'unknown'
        
        # Check common signatures
        if file_data.startswith(b'\x4d\x5a'):
            return 'executable'
        elif file_data.startswith(b'\x7fELF'):
            return 'elf_executable'
        elif file_data.startswith(b'%PDF'):
            return 'pdf'
        elif file_data.startswith(b'PK'):
            return 'archive'
        elif file_data.startswith(b'\x89PNG'):
            return 'image'
        elif file_data.startswith(b'\xff\xd8\xff'):
            return 'jpeg'
        elif b'<html' in file_data[:100].lower():
            return 'html'
        elif b'<?xml' in file_data[:100]:
            return 'xml'
        
        return 'unknown'
    
    def _find_suspicious_indicators(self, results):
        """Find suspicious indicators across all analysis results"""
        indicators = []
        
        # High entropy indicators
        entropy_data = results.get('entropy', {})
        if entropy_data.get('overall_entropy', 0) > 7.5:
            indicators.append({
                'type': 'high_entropy',
                'severity': 'medium',
                'description': f"High entropy detected ({entropy_data['overall_entropy']:.2f}) - possible encryption or packing"
            })
        
        # Suspicious patterns
        patterns = results.get('patterns', {})
        if patterns.get('bitcoin_addresses'):
            indicators.append({
                'type': 'cryptocurrency',
                'severity': 'high',
                'description': f"Bitcoin addresses found: {len(patterns['bitcoin_addresses'])}"
            })
        
        if patterns.get('api_injection_operations'):
            indicators.append({
                'type': 'code_injection',
                'severity': 'high',
                'description': "Code injection APIs detected"
            })
        
        if patterns.get('api_persistence_operations'):
            indicators.append({
                'type': 'persistence',
                'severity': 'medium',
                'description': "Persistence mechanism APIs detected"
            })
        
        # File signature mismatches
        file_info = results.get('file_info', {})
        signature_info = results.get('file_signature', {})
        
        file_ext = file_info.get('extension', '').lower()
        detected_type = signature_info.get('primary_type', 'unknown')
        
        if file_ext == '.pdf' and detected_type != 'pdf':
            indicators.append({
                'type': 'signature_mismatch',
                'severity': 'medium',
                'description': f"File extension ({file_ext}) doesn't match detected type ({detected_type})"
            })
        
        # Large number of suspicious strings
        strings_data = results.get('strings', {})
        total_strings = strings_data.get('total_ascii', 0) + strings_data.get('total_unicode', 0)
        
        if total_strings > 1000:
            indicators.append({
                'type': 'excessive_strings',
                'severity': 'low',
                'description': f"Large number of strings found ({total_strings}) - possible obfuscation"
            })
        
        return indicators
    
    def _assess_threat_level(self, results):
        """Assess overall threat level based on analysis results"""
        score = 0
        reasons = []
        
        # Entropy-based scoring
        entropy_data = results.get('entropy', {})
        entropy_value = entropy_data.get('overall_entropy', 0)
        
        if entropy_value > 7.5:
            score += 30
            reasons.append(f"High entropy ({entropy_value:.2f}) suggests encryption/packing")
        elif entropy_value > 6.5:
            score += 15
            reasons.append(f"Moderate entropy ({entropy_value:.2f})")
        
        # Pattern-based scoring
        patterns = results.get('patterns', {})
        
        if patterns.get('bitcoin_addresses'):
            score += 40
            reasons.append("Cryptocurrency addresses found")
        
        if patterns.get('api_injection_operations'):
            score += 50
            reasons.append("Code injection APIs detected")
        
        if patterns.get('api_debug_operations'):
            score += 20
            reasons.append("Anti-debugging techniques detected")
        
        if patterns.get('api_persistence_operations'):
            score += 30
            reasons.append("Persistence mechanisms detected")
        
        if patterns.get('base64_data'):
            score += 10
            reasons.append("Base64 encoded data found")
        
        # Suspicious indicators scoring
        indicators = results.get('suspicious_indicators', [])
        high_severity_count = len([i for i in indicators if i.get('severity') == 'high'])
        medium_severity_count = len([i for i in indicators if i.get('severity') == 'medium'])
        
        score += high_severity_count * 25
        score += medium_severity_count * 10
        
        # Determine threat level
        if score >= 80:
            level = 'CRITICAL'
        elif score >= 60:
            level = 'HIGH'
        elif score >= 30:
            level = 'MEDIUM'
        elif score >= 10:
            level = 'LOW'
        else:
            level = 'CLEAN'
        
        return {
            'level': level,
            'score': min(score, 100),  # Cap at 100
            'reasons': reasons,
            'confidence': 'high' if score >= 50 else 'medium' if score >= 20 else 'low'
        }
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        
        return f"{s} {size_names[i]}"
