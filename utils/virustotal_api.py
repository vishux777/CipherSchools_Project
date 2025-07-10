import requests
import hashlib
import time
import json
from typing import Dict, Any, Optional

class VirusTotalAPI:
    """VirusTotal API integration for malware scanning"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            "apikey": self.api_key,
            "User-Agent": "MalwareShield-Pro/1.0"
        }
        
    def scan_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Scan file with VirusTotal"""
        if not self.api_key:
            return {"error": "No API key provided"}
        
        try:
            # Calculate file hash first for lookup
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # First try to get existing report
            report = self.get_file_report(file_hash)
            
            if report and 'scans' in report:
                return self._process_report(report)
            
            # If no existing report, submit file for scanning
            scan_result = self._submit_file(file_data, filename)
            
            if 'scan_id' in scan_result:
                # Wait a bit and try to get the report
                time.sleep(15)  # VirusTotal needs time to process
                report = self.get_scan_report(scan_result['scan_id'])
                
                if report and 'scans' in report:
                    return self._process_report(report)
                else:
                    return {
                        "scan_id": scan_result['scan_id'],
                        "status": "submitted",
                        "message": "File submitted for analysis. Report will be available shortly."
                    }
            else:
                return {"error": "Failed to submit file for scanning"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get existing file report by hash"""
        try:
            url = f"{self.base_url}/file/report"
            params = {"apikey": self.api_key, "resource": file_hash}
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return data
            
            return None
            
        except Exception as e:
            print(f"Error getting file report: {e}")
            return None
    
    def get_scan_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan report by scan ID"""
        try:
            url = f"{self.base_url}/file/report"
            params = {"apikey": self.api_key, "resource": scan_id}
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return data
            
            return None
            
        except Exception as e:
            print(f"Error getting scan report: {e}")
            return None
    
    def _submit_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Submit file for scanning"""
        url = f"{self.base_url}/file/scan"
        
        files = {"file": (filename, file_data)}
        data = {"apikey": self.api_key}
        
        response = requests.post(url, files=files, data=data, timeout=60)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise requests.exceptions.RequestException(f"HTTP {response.status_code}")
    
    def _process_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Process VirusTotal report into standardized format"""
        try:
            scans = report.get('scans', {})
            
            # Count detection results
            stats = {
                'total': len(scans),
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0
            }
            
            engines = []
            
            for engine_name, result in scans.items():
                detected = result.get('detected', False)
                detection_name = result.get('result', '')
                
                if detected:
                    if any(keyword in detection_name.lower() for keyword in ['trojan', 'virus', 'malware', 'backdoor']):
                        category = 'malicious'
                        stats['malicious'] += 1
                    else:
                        category = 'suspicious'
                        stats['suspicious'] += 1
                else:
                    category = 'harmless'
                    stats['harmless'] += 1
                
                engines.append({
                    'engine': engine_name,
                    'result': category,
                    'detection': detection_name if detected else 'Clean',
                    'version': result.get('version', 'Unknown'),
                    'update': result.get('update', 'Unknown')
                })
            
            stats['undetected'] = stats['total'] - stats['malicious'] - stats['suspicious'] - stats['harmless']
            
            return {
                'stats': stats,
                'engines': engines,
                'scan_date': report.get('scan_date', ''),
                'scan_id': report.get('scan_id', ''),
                'permalink': report.get('permalink', ''),
                'total': report.get('total', 0),
                'positives': report.get('positives', 0)
            }
            
        except Exception as e:
            return {"error": f"Error processing report: {str(e)}"}
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL analysis report"""
        try:
            api_url = f"{self.base_url}/url/report"
            params = {"apikey": self.api_key, "resource": url}
            
            response = requests.get(api_url, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"error": f"Error getting URL report: {str(e)}"}
    
    def submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis"""
        try:
            api_url = f"{self.base_url}/url/scan"
            data = {"apikey": self.api_key, "url": url}
            
            response = requests.post(api_url, data=data, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"error": f"Error submitting URL: {str(e)}"}
    
    def check_api_key(self) -> bool:
        """Check if API key is valid"""
        if not self.api_key:
            return False
        
        try:
            # Test with a known hash
            test_hash = "d41d8cd98f00b204e9800998ecf8427e"  # Empty file hash
            report = self.get_file_report(test_hash)
            return True  # If no exception, API key works
        except:
            return False
