import requests
import hashlib
import time
from typing import Dict, Any, Optional

class VirusTotalAPI:
    """VirusTotal API integration for malware scanning"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            'apikey': self.api_key
        }
        
    def scan_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Scan file with VirusTotal"""
        if not self.api_key:
            return {
                'error': 'No API key provided',
                'status': 'error'
            }
            
        try:
            # Calculate file hash for lookup
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # First try to get existing report
            existing_report = self.get_file_report(file_hash)
            if existing_report and existing_report.get('response_code') == 1:
                return self._process_report(existing_report)
            
            # If no existing report, submit file
            return self._submit_file(file_data, filename)
            
        except Exception as e:
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'status': 'error'
            }
    
    def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get existing file report by hash"""
        try:
            url = f"{self.base_url}/file/report"
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            print(f"Error getting file report: {e}")
            return None
    
    def _submit_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Submit file for scanning"""
        try:
            url = f"{self.base_url}/file/scan"
            
            files = {'file': (filename, file_data)}
            data = {'apikey': self.api_key}
            
            response = requests.post(url, files=files, data=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            
            return {
                'status': 'submitted',
                'scan_id': result.get('scan_id'),
                'message': 'File submitted successfully'
            }
                
        except Exception as e:
            return {
                'error': f'File submission failed: {str(e)}',
                'status': 'error'
            }
    
    def _process_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Process VirusTotal report into standardized format"""
        try:
            scans = report.get('scans', {})
            
            stats = {
                'malicious': 0,
                'clean': 0,
                'suspicious': 0,
                'total': len(scans)
            }
            
            detections = []
            
            for engine, result in scans.items():
                if result.get('detected'):
                    stats['malicious'] += 1
                    detections.append({
                        'engine': engine,
                        'result': result.get('result', 'Unknown')
                    })
                else:
                    stats['clean'] += 1
            
            return {
                'status': 'complete',
                'stats': stats,
                'detections': detections,
                'sha256': report.get('sha256')
            }
            
        except Exception as e:
            return {
                'error': f'Error processing report: {str(e)}',
                'status': 'error'
            }
    
    def check_api_key(self) -> bool:
        """Check if API key is valid"""
        return bool(self.api_key)