"""
VirusTotal API Integration for MalwareShield Pro
Handles file scanning and report retrieval from VirusTotal

Built with 🛡️ by [Vishwas]
"""

import requests
import hashlib
import time
import os
from typing import Dict, Any, Optional

class VirusTotalAPI:
    """VirusTotal API client for malware scanning"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        self.timeout = 30
    
    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key and self.api_key.strip())
    
    def scan_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """
        Scan file with VirusTotal
        
        Args:
            file_data: Raw file bytes
            filename: Original filename
            
        Returns:
            Dict containing scan results
        """
        if not self.is_configured():
            return {"error": "VirusTotal API key not configured"}
        
        try:
            # Calculate file hash first
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Check if file already exists in VT database
            existing_report = self.get_file_report(file_hash)
            if existing_report and 'error' not in existing_report:
                return existing_report
            
            # File not in database, upload for scanning
            return self._upload_file(file_data, filename)
            
        except Exception as e:
            return {"error": f"VirusTotal scan failed: {str(e)}"}
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get existing file report from VirusTotal
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Dict containing report data
        """
        if not self.is_configured():
            return {"error": "VirusTotal API key not configured"}
        
        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 200:
                return self._parse_report(response.json())
            elif response.status_code == 404:
                return {"error": "File not found in VirusTotal database"}
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"VirusTotal report retrieval failed: {str(e)}"}
    
    def _upload_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Upload file to VirusTotal for scanning"""
        try:
            # Check file size limit (32MB for free API)
            if len(file_data) > 32 * 1024 * 1024:
                return {"error": "File too large for VirusTotal (max 32MB)"}
            
            # Get upload URL
            url = f"{self.base_url}/files"
            files = {"file": (filename, file_data)}
            
            response = requests.post(
                url,
                files=files,
                headers={"x-apikey": self.api_key},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('data', {}).get('id')
                
                if analysis_id:
                    # Wait for analysis to complete
                    return self._wait_for_analysis(analysis_id)
                else:
                    return {"error": "Failed to get analysis ID"}
            else:
                return {"error": f"Upload failed: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"File upload failed: {str(e)}"}
    
    def _wait_for_analysis(self, analysis_id: str, max_wait: int = 300) -> Dict[str, Any]:
        """Wait for analysis to complete"""
        try:
            url = f"{self.base_url}/analyses/{analysis_id}"
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    status = attributes.get('status')
                    
                    if status == 'completed':
                        # Get the file report
                        stats = attributes.get('stats', {})
                        file_info = attributes.get('meta', {}).get('file_info', {})
                        
                        return {
                            'scan_date': attributes.get('date'),
                            'status': status,
                            'total_scans': sum(stats.values()),
                            'positive_scans': stats.get('malicious', 0),
                            'stats': stats,
                            'file_info': file_info,
                            'permalink': f"https://www.virustotal.com/gui/file/{file_info.get('sha256', '')}"
                        }
                    elif status == 'queued':
                        time.sleep(5)  # Wait 5 seconds before checking again
                    else:
                        return {"error": f"Analysis failed with status: {status}"}
                else:
                    return {"error": f"Analysis check failed: {response.status_code}"}
            
            return {"error": "Analysis timeout - please check VirusTotal manually"}
            
        except Exception as e:
            return {"error": f"Analysis wait failed: {str(e)}"}
    
    def _parse_report(self, report_data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal report data"""
        try:
            data = report_data.get('data', {})
            attributes = data.get('attributes', {})
            
            # Extract scan results
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            last_analysis_results = attributes.get('last_analysis_results', {})
            
            # File information
            file_info = {
                'sha256': attributes.get('sha256'),
                'sha1': attributes.get('sha1'),
                'md5': attributes.get('md5'),
                'file_size': attributes.get('size'),
                'file_type': attributes.get('type_description'),
                'magic': attributes.get('magic'),
                'first_seen': attributes.get('first_submission_date'),
                'last_seen': attributes.get('last_submission_date')
            }
            
            # Scan statistics
            total_scans = sum(last_analysis_stats.values())
            positive_scans = last_analysis_stats.get('malicious', 0)
            
            # Engine results
            engines = []
            for engine_name, result in last_analysis_results.items():
                engines.append({
                    'name': engine_name,
                    'result': result.get('result'),
                    'category': result.get('category'),
                    'version': result.get('version'),
                    'update': result.get('update')
                })
            
            return {
                'scan_date': attributes.get('last_analysis_date'),
                'total_scans': total_scans,
                'positive_scans': positive_scans,
                'detection_ratio': f"{positive_scans}/{total_scans}",
                'stats': last_analysis_stats,
                'file_info': file_info,
                'engines': engines,
                'permalink': f"https://www.virustotal.com/gui/file/{file_info['sha256']}"
            }
            
        except Exception as e:
            return {"error": f"Failed to parse VirusTotal report: {str(e)}"}
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL analysis report"""
        if not self.is_configured():
            return {"error": "VirusTotal API key not configured"}
        
        try:
            # Encode URL for API
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            api_url = f"{self.base_url}/urls/{url_id}"
            response = requests.get(api_url, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 200:
                return self._parse_url_report(response.json())
            elif response.status_code == 404:
                return {"error": "URL not found in VirusTotal database"}
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"URL report retrieval failed: {str(e)}"}
    
    def _parse_url_report(self, report_data: Dict) -> Dict[str, Any]:
        """Parse URL report data"""
        try:
            data = report_data.get('data', {})
            attributes = data.get('attributes', {})
            
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            return {
                'url': attributes.get('url'),
                'scan_date': attributes.get('last_analysis_date'),
                'total_scans': sum(last_analysis_stats.values()),
                'positive_scans': last_analysis_stats.get('malicious', 0),
                'stats': last_analysis_stats,
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'permalink': f"https://www.virustotal.com/gui/url/{data.get('id', '')}"
            }
            
        except Exception as e:
            return {"error": f"Failed to parse URL report: {str(e)}"}
