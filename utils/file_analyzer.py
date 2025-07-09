import hashlib
import math
import re
import string
import magic
from collections import Counter
from typing import Dict, List, Any, Optional

class FileAnalyzer:
    """Comprehensive file analysis utilities for static malware analysis"""
    
    def __init__(self):
        # Initialize magic for file type detection
        try:
            self.magic_mime = magic.Magic(mime=True)
            self.magic_type = magic.Magic()
        except:
            self.magic_mime = None
            self.magic_type = None
    
    def calculate_hashes(self, file_data: bytes) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of file data"""
        return {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest()
        }
    
    def calculate_entropy(self, file_data: bytes) -> float:
        """Calculate Shannon entropy of file data"""
        if len(file_data) == 0:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(file_data)
        file_length = len(file_data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / file_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 3)
    
    def extract_strings(self, file_data: bytes, max_strings: int = 100, min_length: int = 5) -> List[str]:
        """Extract printable strings from file data"""
        # Create pattern for printable ASCII strings
        pattern = re.compile(b'[' + string.printable.encode('ascii') + b']{' + str(min_length).encode('ascii') + b',}')
        matches = pattern.findall(file_data)
        
        strings = []
        for match in matches:
            try:
                decoded_string = match.decode('ascii', errors='ignore').strip()
                if len(decoded_string) >= min_length:
                    strings.append(decoded_string)
            except:
                continue
        
        # Remove duplicates while preserving order
        unique_strings = []
        seen = set()
        for s in strings:
            if s not in seen:
                unique_strings.append(s)
                seen.add(s)
                if len(unique_strings) >= max_strings:
                    break
        
        return unique_strings
    
    def detect_patterns(self, file_data: bytes) -> Dict[str, List[str]]:
        """Detect various patterns in file data (URLs, IPs, emails, etc.)"""
        try:
            # Try to decode as text
            text_data = file_data.decode('utf-8', errors='ignore')
        except:
            text_data = str(file_data)
        
        patterns = {
            'urls': [],
            'ips': [],
            'emails': [],
            'domains': [],
            'file_paths': [],
            'registry_keys': []
        }
        
        # URL pattern (improved)
        url_pattern = re.compile(r'https?://[^\s<>"{}\|\\^`\[\]]+', re.IGNORECASE)
        patterns['urls'] = list(set(url_pattern.findall(text_data)))[:10]
        
        # IP address pattern
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        potential_ips = ip_pattern.findall(text_data)
        # Validate IPs
        valid_ips = []
        for ip in potential_ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        patterns['ips'] = list(set(valid_ips))[:10]
        
        # Email pattern
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        patterns['emails'] = list(set(email_pattern.findall(text_data)))[:10]
        
        # Domain pattern
        domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b')
        patterns['domains'] = list(set(match[0] + '.' + match[1] for match in domain_pattern.findall(text_data)))[:10]
        
        # File path patterns (Windows and Unix)
        file_path_pattern = re.compile(r'[A-Za-z]:\\[^\s<>"|?*]+|/[^\s<>"|?*]+')
        patterns['file_paths'] = list(set(file_path_pattern.findall(text_data)))[:10]
        
        # Windows registry key pattern
        registry_pattern = re.compile(r'HKEY_[A-Z_]+\\[^\s<>"|?*]+', re.IGNORECASE)
        patterns['registry_keys'] = list(set(registry_pattern.findall(text_data)))[:10]
        
        return patterns
    
    def extract_metadata(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Extract file metadata and additional information"""
        metadata = {
            'filename': filename,
            'size': len(file_data),
            'size_human': self._format_file_size(len(file_data))
        }
        
        # File type detection using magic
        if self.magic_mime and self.magic_type:
            try:
                metadata['mime_type'] = self.magic_mime.from_buffer(file_data)
                metadata['file_type'] = self.magic_type.from_buffer(file_data)
            except:
                metadata['mime_type'] = 'unknown'
                metadata['file_type'] = 'unknown'
        else:
            metadata['mime_type'] = 'unknown'
            metadata['file_type'] = 'unknown'
        
        # File extension
        if '.' in filename:
            metadata['extension'] = filename.split('.')[-1].lower()
        else:
            metadata['extension'] = 'none'
        
        # Basic file analysis
        metadata['null_bytes'] = file_data.count(b'\x00')
        metadata['null_percentage'] = (metadata['null_bytes'] / len(file_data)) * 100 if len(file_data) > 0 else 0
        
        # Byte distribution analysis
        byte_counts = Counter(file_data)
        metadata['unique_bytes'] = len(byte_counts)
        metadata['most_common_byte'] = byte_counts.most_common(1)[0] if byte_counts else (0, 0)
        
        # Check for common file signatures
        metadata['file_signature'] = self._check_file_signatures(file_data)
        
        # PE file specific analysis
        if file_data.startswith(b'MZ'):
            metadata['pe_analysis'] = self._analyze_pe_file(file_data)
        
        # Archive detection
        metadata['is_archive'] = self._is_archive_file(file_data, filename)
        
        return metadata
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    def _check_file_signatures(self, file_data: bytes) -> Dict[str, Any]:
        """Check for common file signatures/magic bytes"""
        signatures = {
            'pe_executable': file_data.startswith(b'MZ'),
            'elf_executable': file_data.startswith(b'\x7fELF'),
            'pdf': file_data.startswith(b'%PDF'),
            'zip': file_data.startswith(b'PK\x03\x04') or file_data.startswith(b'PK\x05\x06'),
            'rar': file_data.startswith(b'Rar!\x1a\x07\x00') or file_data.startswith(b'Rar!\x1a\x07\x01\x00'),
            'gzip': file_data.startswith(b'\x1f\x8b'),
            'bzip2': file_data.startswith(b'BZ'),
            'jpeg': file_data.startswith(b'\xff\xd8\xff'),
            'png': file_data.startswith(b'\x89PNG\r\n\x1a\n'),
            'gif': file_data.startswith(b'GIF87a') or file_data.startswith(b'GIF89a')
        }
        
        detected = [sig_type for sig_type, detected in signatures.items() if detected]
        
        return {
            'detected_types': detected,
            'primary_type': detected[0] if detected else 'unknown'
        }
    
    def _analyze_pe_file(self, file_data: bytes) -> Dict[str, Any]:
        """Basic PE file analysis"""
        pe_info = {
            'is_pe': True,
            'is_dll': False,
            'is_exe': False,
            'machine_type': 'unknown',
            'sections': 0
        }
        
        try:
            # Check for PE signature
            if len(file_data) > 0x3c:
                pe_offset = int.from_bytes(file_data[0x3c:0x40], 'little')
                if len(file_data) > pe_offset + 4:
                    pe_signature = file_data[pe_offset:pe_offset+4]
                    if pe_signature == b'PE\x00\x00':
                        # Read COFF header
                        coff_start = pe_offset + 4
                        if len(file_data) > coff_start + 20:
                            machine = int.from_bytes(file_data[coff_start:coff_start+2], 'little')
                            sections = int.from_bytes(file_data[coff_start+2:coff_start+4], 'little')
                            characteristics = int.from_bytes(file_data[coff_start+18:coff_start+20], 'little')
                            
                            pe_info['machine_type'] = self._get_machine_type(machine)
                            pe_info['sections'] = sections
                            pe_info['is_dll'] = bool(characteristics & 0x2000)
                            pe_info['is_exe'] = not pe_info['is_dll']
        except:
            pass
        
        return pe_info
    
    def _get_machine_type(self, machine_value: int) -> str:
        """Get machine type from PE machine value"""
        machine_types = {
            0x14c: 'i386',
            0x8664: 'x86_64',
            0x1c0: 'ARM',
            0xaa64: 'ARM64',
            0x200: 'IA64'
        }
        return machine_types.get(machine_value, f'unknown_{hex(machine_value)}')
    
    def _is_archive_file(self, file_data: bytes, filename: str) -> bool:
        """Check if file is an archive"""
        archive_signatures = [
            b'PK\x03\x04',  # ZIP
            b'PK\x05\x06',  # ZIP (empty)
            b'Rar!\x1a\x07\x00',  # RAR
            b'Rar!\x1a\x07\x01\x00',  # RAR
            b'\x1f\x8b',  # GZIP
            b'BZ',  # BZIP2
            b'7z\xbc\xaf\x27\x1c'  # 7ZIP
        ]
        
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz']
        
        # Check signatures
        for sig in archive_signatures:
            if file_data.startswith(sig):
                return True
        
        # Check extension
        for ext in archive_extensions:
            if filename.lower().endswith(ext):
                return True
        
        return False
    
    def analyze_suspicious_patterns(self, file_data: bytes) -> Dict[str, Any]:
        """Analyze for suspicious patterns commonly found in malware"""
        suspicious_patterns = {
            'obfuscation_indicators': [],
            'suspicious_strings': [],
            'encoding_patterns': [],
            'suspicious_apis': []
        }
        
        try:
            text_data = file_data.decode('utf-8', errors='ignore')
        except:
            text_data = str(file_data)
        
        # Check for base64 encoded content
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        base64_matches = base64_pattern.findall(text_data)
        if len(base64_matches) > 5:
            suspicious_patterns['encoding_patterns'].append('Multiple base64 strings detected')
        
        # Check for hex encoded content
        hex_pattern = re.compile(r'[0-9a-fA-F]{40,}')
        hex_matches = hex_pattern.findall(text_data)
        if len(hex_matches) > 3:
            suspicious_patterns['encoding_patterns'].append('Multiple hex strings detected')
        
        # Suspicious API calls (Windows)
        suspicious_apis = [
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc', 'LoadLibrary',
            'GetProcAddress', 'RegSetValue', 'InternetOpen', 'URLDownloadToFile',
            'CreateFile', 'WriteFile', 'SetFileAttributes'
        ]
        
        for api in suspicious_apis:
            if api.lower() in text_data.lower():
                suspicious_patterns['suspicious_apis'].append(api)
        
        # Obfuscation indicators
        if text_data.count('\\x') > 20:
            suspicious_patterns['obfuscation_indicators'].append('High number of hex escape sequences')
        
        if len(re.findall(r'[A-Za-z]{1}[0-9]+[A-Za-z]+', text_data)) > 10:
            suspicious_patterns['obfuscation_indicators'].append('Suspicious variable naming patterns')
        
        return suspicious_patterns
