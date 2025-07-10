import hashlib
import math
import re
import string
from collections import Counter
from typing import Dict, List, Any, Optional
import time

class AnalysisEngine:
    """Core analysis engine for malware detection"""
    
    def __init__(self):
        self.suspicious_strings = [
            # Network-related
            'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',
            'http', 'https', 'ftp', 'smtp', 'dns', 'tcp', 'udp',
            
            # File operations
            'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile',
            'MoveFile', 'GetTempPath', 'GetSystemDirectory',
            
            # Registry operations
            'RegOpenKey', 'RegSetValue', 'RegDeleteKey', 'RegCreateKey',
            'HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER',
            
            # Process operations
            'CreateProcess', 'TerminateProcess', 'OpenProcess', 'GetProcAddress',
            'LoadLibrary', 'VirtualAlloc', 'VirtualProtect',
            
            # Cryptographic
            'CryptAcquireContext', 'CryptGenKey', 'CryptEncrypt', 'CryptDecrypt',
            'MD5', 'SHA1', 'SHA256', 'AES', 'DES', 'RC4',
            
            # Anti-analysis
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetTickCount',
            'Sleep', 'anti', 'debug', 'virtual', 'sandbox', 'analysis',
            
            # Malicious keywords
            'backdoor', 'trojan', 'virus', 'worm', 'rootkit', 'keylog',
            'stealer', 'rat', 'botnet', 'payload', 'exploit', 'shellcode'
        ]
        
        self.file_extensions = {
            'executable': ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.pif'],
            'document': ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'script': ['.js', '.vbs', '.ps1', '.py', '.pl', '.php'],
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp'],
            'media': ['.mp3', '.mp4', '.avi', '.mov', '.wav']
        }
    
    def calculate_hashes(self, file_data: bytes) -> Dict[str, str]:
        """Calculate cryptographic hashes"""
        return {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'sha512': hashlib.sha512(file_data).hexdigest()
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
        
        return round(entropy, 6)
    
    def extract_strings(self, file_data: bytes, max_strings: int = 200, min_length: int = 5) -> List[str]:
        """Extract printable strings from file data"""
        try:
            # Pattern for printable ASCII strings
            string_pattern = re.compile(
                b'[' + string.printable.encode('ascii') + b']{' + 
                str(min_length).encode('ascii') + b',}'
            )
            
            matches = string_pattern.findall(file_data)
            strings = []
            
            for match in matches:
                try:
                    decoded_string = match.decode('ascii', errors='ignore').strip()
                    if (len(decoded_string) >= min_length and 
                        decoded_string not in strings and
                        self._is_meaningful_string(decoded_string)):
                        strings.append(decoded_string)
                        
                        if len(strings) >= max_strings:
                            break
                except:
                    continue
            
            return strings
            
        except Exception as e:
            print(f"Error extracting strings: {e}")
            return []
    
    def detect_patterns(self, file_data: bytes) -> Dict[str, List[str]]:
        """Detect various suspicious patterns"""
        try:
            # Convert to string for pattern matching
            text_data = file_data.decode('utf-8', errors='ignore')
        except:
            text_data = str(file_data)
        
        patterns = {
            'urls': self._extract_urls(text_data),
            'ips': self._extract_ips(text_data),
            'emails': self._extract_emails(text_data),
            'registry_keys': self._extract_registry_keys(text_data),
            'file_paths': self._extract_file_paths(text_data),
            'suspicious_strings': self._find_suspicious_strings(text_data),
            'base64_strings': self._extract_base64_strings(text_data),
            'hex_strings': self._extract_hex_strings(text_data)
        }
        
        return patterns
    
    def behavioral_analysis(self, file_data: bytes) -> Dict[str, Any]:
        """Perform behavioral analysis of the file"""
        indicators = []
        capabilities = []
        risk_score = 0
        
        # Check for suspicious imports/APIs
        api_calls = self._detect_api_calls(file_data)
        if api_calls:
            indicators.append({
                'title': 'Suspicious API Calls Detected',
                'description': f'Found {len(api_calls)} potentially malicious API calls',
                'severity': 'medium'
            })
            risk_score += len(api_calls) * 2
            
            capabilities.extend([{
                'capability': 'API Usage',
                'details': ', '.join(api_calls[:10]),
                'risk_level': 'medium'
            }])
        
        # Check for packing/encryption
        entropy = self.calculate_entropy(file_data)
        if entropy > 7.5:
            indicators.append({
                'title': 'High Entropy Detected',
                'description': 'File may be packed or encrypted to evade detection',
                'severity': 'high'
            })
            risk_score += 25
            
            capabilities.append({
                'capability': 'Evasion Technique',
                'details': f'High entropy ({entropy:.2f}) suggests packing/encryption',
                'risk_level': 'high'
            })
        
        # Check for suspicious strings
        strings = self.extract_strings(file_data, max_strings=500)
        suspicious_count = sum(1 for s in strings if any(sus in s.lower() for sus in self.suspicious_strings))
        
        if suspicious_count > 5:
            indicators.append({
                'title': 'Suspicious String Patterns',
                'description': f'Found {suspicious_count} strings matching malicious patterns',
                'severity': 'medium' if suspicious_count < 20 else 'high'
            })
            risk_score += suspicious_count
            
            capabilities.append({
                'capability': 'Suspicious Functionality',
                'details': f'{suspicious_count} suspicious string patterns detected',
                'risk_level': 'medium' if suspicious_count < 20 else 'high'
            })
        
        # Check for network indicators
        patterns = self.detect_patterns(file_data)
        network_indicators = len(patterns['urls']) + len(patterns['ips'])
        
        if network_indicators > 3:
            indicators.append({
                'title': 'Network Communication Capability',
                'description': f'Found {network_indicators} network-related indicators',
                'severity': 'medium'
            })
            risk_score += network_indicators * 3
            
            capabilities.append({
                'capability': 'Network Communication',
                'details': f'{len(patterns["urls"])} URLs, {len(patterns["ips"])} IPs detected',
                'risk_level': 'medium'
            })
        
        # Check for anti-analysis techniques
        anti_analysis_indicators = [
            'debugger', 'virtual', 'sandbox', 'analysis', 'hook',
            'breakpoint', 'trace', 'monitor'
        ]
        
        anti_analysis_count = 0
        for string in strings:
            if any(indicator in string.lower() for indicator in anti_analysis_indicators):
                anti_analysis_count += 1
        
        if anti_analysis_count > 2:
            indicators.append({
                'title': 'Anti-Analysis Techniques',
                'description': f'Found {anti_analysis_count} anti-analysis indicators',
                'severity': 'high'
            })
            risk_score += anti_analysis_count * 5
            
            capabilities.append({
                'capability': 'Evasion',
                'details': f'Anti-analysis techniques detected',
                'risk_level': 'high'
            })
        
        # Normalize risk score to 0-100
        risk_score = min(risk_score, 100)
        
        return {
            'indicators': indicators,
            'capabilities': capabilities,
            'risk_score': risk_score,
            'analysis_time': time.time()
        }
    
    def calculate_threat_assessment(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall threat assessment"""
        risk_score = 0
        risk_factors = []
        
        # Entropy analysis
        if 'entropy' in analysis_results:
            entropy = analysis_results['entropy']
            if entropy > 7.5:
                risk_score += 30
                risk_factors.append("Very high entropy (likely packed/encrypted)")
            elif entropy > 7:
                risk_score += 20
                risk_factors.append("High entropy (may be compressed)")
            elif entropy > 6:
                risk_score += 10
                risk_factors.append("Elevated entropy")
        
        # VirusTotal results
        if 'virustotal' in analysis_results:
            vt_data = analysis_results['virustotal']
            if 'stats' in vt_data:
                malicious_count = vt_data['stats']['malicious']
                if malicious_count > 5:
                    risk_score += 40
                    risk_factors.append(f"{malicious_count} engines flagged as malicious")
                elif malicious_count > 2:
                    risk_score += 25
                    risk_factors.append(f"{malicious_count} engines flagged as malicious")
                elif malicious_count > 0:
                    risk_score += 15
                    risk_factors.append(f"{malicious_count} engines flagged as malicious")
        
        # Pattern detection
        if 'patterns' in analysis_results:
            patterns = analysis_results['patterns']
            
            # Suspicious strings
            if patterns.get('suspicious_strings'):
                count = len(patterns['suspicious_strings'])
                if count > 10:
                    risk_score += 25
                    risk_factors.append(f"{count} suspicious strings detected")
                elif count > 5:
                    risk_score += 15
                    risk_factors.append(f"{count} suspicious strings detected")
            
            # Network indicators
            network_count = len(patterns.get('urls', [])) + len(patterns.get('ips', []))
            if network_count > 10:
                risk_score += 20
                risk_factors.append(f"{network_count} network indicators")
            elif network_count > 5:
                risk_score += 10
                risk_factors.append(f"{network_count} network indicators")
        
        # Behavioral analysis
        if 'behavioral' in analysis_results:
            behavioral = analysis_results['behavioral']
            behavioral_risk = behavioral.get('risk_score', 0)
            
            # Add a portion of behavioral risk
            risk_score += int(behavioral_risk * 0.3)
            
            high_severity_indicators = [
                ind for ind in behavioral.get('indicators', [])
                if ind.get('severity') == 'high'
            ]
            
            if high_severity_indicators:
                risk_factors.append(f"{len(high_severity_indicators)} high-severity behavioral indicators")
        
        # String analysis
        if 'strings' in analysis_results:
            string_count = len(analysis_results['strings'])
            if string_count > 500:
                risk_score += 10
                risk_factors.append("Very high number of strings")
        
        # Determine threat level
        if risk_score >= 70:
            threat_level = "Critical"
        elif risk_score >= 50:
            threat_level = "High"
        elif risk_score >= 30:
            threat_level = "Medium"
        else:
            threat_level = "Low"
        
        return {
            'level': threat_level,
            'score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'assessment_time': time.time()
        }
    
    def _is_meaningful_string(self, string: str) -> bool:
        """Check if string is meaningful (not just random characters)"""
        # Filter out strings that are mostly numbers or special characters
        if len(string.strip()) < 4:
            return False
        
        # Check if it's mostly alphanumeric
        alphanumeric_count = sum(1 for c in string if c.isalnum())
        if alphanumeric_count / len(string) < 0.6:
            return False
        
        # Filter out strings with too many repeating characters
        if len(set(string)) < len(string) / 3:
            return False
        
        return True
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        return list(set(url_pattern.findall(text)))[:20]
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )
        return list(set(ip_pattern.findall(text)))[:20]
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        return list(set(email_pattern.findall(text)))[:20]
    
    def _extract_registry_keys(self, text: str) -> List[str]:
        """Extract Windows registry keys"""
        registry_pattern = re.compile(
            r'HKEY_[A-Z_]+\\[^\s\x00-\x1f\x7f-\x9f]+',
            re.IGNORECASE
        )
        return list(set(registry_pattern.findall(text)))[:20]
    
    def _extract_file_paths(self, text: str) -> List[str]:
        """Extract file paths"""
        # Windows paths
        win_path_pattern = re.compile(r'[A-Za-z]:\\[^\s\x00-\x1f\x7f-\x9f<>"|*?]+')
        win_paths = win_path_pattern.findall(text)
        
        # Unix paths
        unix_path_pattern = re.compile(r'/[^\s\x00-\x1f\x7f-\x9f]+')
        unix_paths = unix_path_pattern.findall(text)
        
        return list(set(win_paths + unix_paths))[:20]
    
    def _find_suspicious_strings(self, text: str) -> List[str]:
        """Find strings matching suspicious patterns"""
        suspicious_found = []
        text_lower = text.lower()
        
        for suspicious in self.suspicious_strings:
            if suspicious.lower() in text_lower:
                # Find the actual string context
                pattern = re.compile(f'[^\s\x00-\x1f\x7f-\x9f]*{re.escape(suspicious)}[^\s\x00-\x1f\x7f-\x9f]*', re.IGNORECASE)
                matches = pattern.findall(text)
                suspicious_found.extend(matches[:3])  # Limit per pattern
        
        return list(set(suspicious_found))[:50]
    
    def _extract_base64_strings(self, text: str) -> List[str]:
        """Extract potential Base64 encoded strings"""
        # Look for Base64 patterns (at least 20 characters)
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        potential_b64 = base64_pattern.findall(text)
        
        # Validate Base64 strings
        valid_b64 = []
        for b64_str in potential_b64:
            try:
                import base64
                base64.b64decode(b64_str, validate=True)
                valid_b64.append(b64_str)
            except:
                continue
        
        return valid_b64[:10]
    
    def _extract_hex_strings(self, text: str) -> List[str]:
        """Extract hexadecimal strings"""
        hex_pattern = re.compile(r'\b[0-9a-fA-F]{16,}\b')
        return list(set(hex_pattern.findall(text)))[:20]
    
    def _detect_api_calls(self, file_data: bytes) -> List[str]:
        """Detect suspicious API calls in binary data"""
        try:
            text_data = file_data.decode('utf-8', errors='ignore')
        except:
            text_data = str(file_data)
        
        suspicious_apis = [
            'CreateProcess', 'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
            'RegSetValue', 'RegCreateKey', 'CreateFile', 'WriteFile', 'CopyFile',
            'socket', 'connect', 'send', 'recv', 'InternetOpen', 'InternetConnect',
            'CryptAcquireContext', 'CryptGenKey', 'IsDebuggerPresent'
        ]
        
        found_apis = []
        for api in suspicious_apis:
            if api in text_data:
                found_apis.append(api)
        
        return found_apis
