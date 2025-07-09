import hashlib
import re
import string
import math
from collections import Counter
from typing import Dict, List, Any
try:
    import magic
except ImportError:
    magic = None

class FileAnalyzer:
    """Comprehensive file analysis utilities for static malware analysis"""
    
    def __init__(self):
        self.suspicious_strings = [
            'CreateRemoteThread', 'VirtualAlloc', 'VirtualProtect', 'LoadLibrary',
            'GetProcAddress', 'WriteProcessMemory', 'ReadProcessMemory',
            'CreateProcess', 'ShellExecute', 'WinExec', 'URLDownloadToFile',
            'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'FtpPutFile',
            'RegOpenKey', 'RegSetValue', 'RegCreateKey', 'CryptAcquireContext',
            'CryptGenKey', 'CryptEncrypt', 'CryptDecrypt', 'keylogger',
            'backdoor', 'rootkit', 'botnet', 'malware', 'virus', 'trojan'
        ]
    
    def calculate_hashes(self, file_data: bytes) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of file data"""
        return {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest()
        }
    
    def calculate_entropy(self, file_data: bytes) -> float:
        """Calculate Shannon entropy of file data"""
        if not file_data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(file_data)
        file_size = len(file_data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / file_size
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def extract_strings(self, file_data: bytes, max_strings: int = 100, min_length: int = 5) -> List[str]:
        """Extract printable strings from file data"""
        strings = []
        current_string = ""
        
        for byte in file_data:
            char = chr(byte)
            if char in string.printable and char not in '\t\n\r\x0b\x0c':
                current_string += char
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                    if len(strings) >= max_strings:
                        break
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length and len(strings) < max_strings:
            strings.append(current_string)
        
        return strings[:max_strings]
    
    def detect_patterns(self, file_data: bytes) -> Dict[str, List[str]]:
        """Detect various patterns in file data (URLs, IPs, emails, etc.)"""
        data_str = file_data.decode('utf-8', errors='ignore')
        
        patterns = {
            'urls': re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data_str),
            'ip_addresses': re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data_str),
            'email_addresses': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', data_str),
            'file_paths': re.findall(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*', data_str),
            'registry_keys': re.findall(r'HKEY_[A-Z_]+\\[^\\s]*', data_str),
            'bitcoin_addresses': re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', data_str)
        }
        
        # Limit results
        for key in patterns:
            patterns[key] = list(set(patterns[key]))[:10]  # Remove duplicates and limit
        
        return patterns
    
    def extract_metadata(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Extract file metadata and additional information"""
        metadata = {
            'filename': filename,
            'file_size': len(file_data),
            'file_type': self._get_file_type(file_data, filename),
            'file_extension': filename.split('.')[-1] if '.' in filename else 'none',
            'is_archive': self._is_archive_file(file_data, filename),
            'file_signature': self._check_file_signatures(file_data)
        }
        
        # Add PE analysis if it's a PE file
        if metadata['file_signature'].get('is_pe', False):
            metadata['pe_analysis'] = self._analyze_pe_file(file_data)
        
        return metadata
    
    def _get_file_type(self, file_data: bytes, filename: str) -> str:
        """Get file type using magic library or fallback to extension"""
        if magic:
            try:
                return magic.from_buffer(file_data, mime=True)
            except:
                pass
        
        # Fallback to extension-based detection
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        ext_map = {
            'exe': 'application/x-executable',
            'dll': 'application/x-library',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'zip': 'application/zip',
            'rar': 'application/x-rar',
            'txt': 'text/plain',
            'js': 'application/javascript',
            'bat': 'application/x-bat',
            'ps1': 'application/x-powershell'
        }
        return ext_map.get(ext, 'application/octet-stream')
    
    def _check_file_signatures(self, file_data: bytes) -> Dict[str, Any]:
        """Check for common file signatures/magic bytes"""
        signatures = {
            'is_pe': file_data.startswith(b'MZ'),
            'is_pdf': file_data.startswith(b'%PDF'),
            'is_zip': file_data.startswith(b'PK'),
            'is_rar': file_data.startswith(b'Rar!'),
            'is_elf': file_data.startswith(b'\x7fELF'),
            'is_java': file_data.startswith(b'\xca\xfe\xba\xbe'),
            'is_office': b'Microsoft Office' in file_data[:1024]
        }
        
        # Determine primary type
        for sig_type, is_match in signatures.items():
            if is_match:
                signatures['primary_type'] = sig_type
                break
        else:
            signatures['primary_type'] = 'unknown'
        
        return signatures
    
    def _analyze_pe_file(self, file_data: bytes) -> Dict[str, Any]:
        """Basic PE file analysis"""
        try:
            if len(file_data) < 64:
                return {'error': 'File too small for PE analysis'}
            
            # DOS header
            e_lfanew = int.from_bytes(file_data[60:64], 'little')
            
            if e_lfanew >= len(file_data) - 24:
                return {'error': 'Invalid PE header offset'}
            
            # PE signature
            pe_sig = file_data[e_lfanew:e_lfanew+4]
            if pe_sig != b'PE\x00\x00':
                return {'error': 'Invalid PE signature'}
            
            # COFF header
            machine = int.from_bytes(file_data[e_lfanew+4:e_lfanew+6], 'little')
            num_sections = int.from_bytes(file_data[e_lfanew+6:e_lfanew+8], 'little')
            timestamp = int.from_bytes(file_data[e_lfanew+8:e_lfanew+12], 'little')
            
            return {
                'machine_type': self._get_machine_type(machine),
                'number_of_sections': num_sections,
                'compilation_timestamp': timestamp,
                'is_32bit': machine in [0x14c, 0x1c0, 0x1c2, 0x1c4],
                'is_64bit': machine in [0x8664, 0x200]
            }
        except Exception as e:
            return {'error': f'PE analysis failed: {str(e)}'}
    
    def _get_machine_type(self, machine_value: int) -> str:
        """Get machine type from PE machine value"""
        machine_types = {
            0x14c: 'Intel 386',
            0x8664: 'x64',
            0x200: 'Intel Itanium',
            0x1c0: 'ARM',
            0x1c2: 'ARM Thumb-2',
            0x1c4: 'ARMv7'
        }
        return machine_types.get(machine_value, f'Unknown (0x{machine_value:x})')
    
    def _is_archive_file(self, file_data: bytes, filename: str) -> bool:
        """Check if file is an archive"""
        archive_signatures = [
            b'PK',  # ZIP
            b'Rar!',  # RAR
            b'7z\xbc\xaf\x27\x1c',  # 7-Zip
            b'\x1f\x8b',  # GZIP
            b'BZh'  # BZIP2
        ]
        
        for sig in archive_signatures:
            if file_data.startswith(sig):
                return True
        
        archive_extensions = ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz']
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        return ext in archive_extensions
    
    def analyze_suspicious_patterns(self, file_data: bytes) -> Dict[str, Any]:
        """Analyze for suspicious patterns commonly found in malware"""
        data_str = file_data.decode('utf-8', errors='ignore')
        
        suspicious_findings = {
            'suspicious_api_calls': [],
            'obfuscation_indicators': [],
            'persistence_indicators': [],
            'network_indicators': [],
            'crypto_indicators': []
        }
        
        # Check for suspicious API calls
        for api_call in self.suspicious_strings:
            if api_call.lower() in data_str.lower():
                suspicious_findings['suspicious_api_calls'].append(api_call)
        
        # Check for obfuscation indicators
        obfuscation_patterns = [
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'\\[0-7]{3}',  # Octal encoding
        ]
        
        for pattern in obfuscation_patterns:
            matches = re.findall(pattern, data_str)
            if matches:
                suspicious_findings['obfuscation_indicators'].extend(matches[:5])
        
        # Check for persistence indicators
        persistence_patterns = [
            r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            r'schtasks\.exe',
            r'at\.exe.*\d{2}:\d{2}',
            r'reg\.exe.*add'
        ]
        
        for pattern in persistence_patterns:
            matches = re.findall(pattern, data_str, re.IGNORECASE)
            if matches:
                suspicious_findings['persistence_indicators'].extend(matches[:3])
        
        # Check for network indicators
        network_patterns = [
            r'socket\s*\(',
            r'connect\s*\(',
            r'send\s*\(',
            r'recv\s*\(',
            r'WSAStartup',
            r'InternetOpen'
        ]
        
        for pattern in network_patterns:
            if re.search(pattern, data_str, re.IGNORECASE):
                suspicious_findings['network_indicators'].append(pattern)
        
        # Check for crypto indicators
        crypto_patterns = [
            r'CryptAcquireContext',
            r'CryptGenKey',
            r'CryptEncrypt',
            r'CryptDecrypt',
            r'MD5|SHA1|SHA256|AES|DES|RC4',
            r'bitcoin|btc|cryptocurrency'
        ]
        
        for pattern in crypto_patterns:
            matches = re.findall(pattern, data_str, re.IGNORECASE)
            if matches:
                suspicious_findings['crypto_indicators'].extend(matches[:3])
        
        # Remove duplicates and limit results
        for key in suspicious_findings:
            suspicious_findings[key] = list(set(suspicious_findings[key]))[:10]
        
        return suspicious_findings