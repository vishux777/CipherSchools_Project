"""
VirusTotal API Integration Module

Provides comprehensive integration with VirusTotal API for file scanning,
hash lookups, and threat intelligence gathering.
"""

import requests
import time
import hashlib
import json
from typing import Dict, Any, Optional

class VirusTotalAPI:
    """VirusTotal API client for malware scanning and analysis"""
    
    def __init__(self, api_key: str):
        """Initialize VirusTotal API client
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        self.session.headers.update({
            'apikey': self.api_key,
            'User-Agent': 'MalwareShield-Pro/1.0'
        })
    
    def is_configured(self) -> bool:
        """Check if API is properly configured
        
        Returns:
            bool: True if API key is valid and configured
        """
        if not self.api_key:
            return False
        
        try:
            # Test API key with a simple request
            response = self.session.get(
                f"{self.base_url}/file/report",
                params={'resource': 'test', 'apikey': self.api_key},
                timeout=10
            )
            return response.status_code != 403
        except Exception:
            return False
    
    def scan_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Scan file with VirusTotal
        
        Args:
            file_data: Binary file data
            filename: Original filename
            
        Returns:
            dict: Scan results from VirusTotal
        """
        try:
            # Calculate file hash for checking existing reports
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # First, check if file was already scanned
            existing_report = self.get_file_report(file_hash)
            if existing_report and 'scans' in existing_report:
                existing_report['source'] = 'existing_report'
                return existing_report
            
            # If no existing report, submit file for scanning
            files = {'file': (filename, file_data)}
            response = self.session.post(
                f"{self.base_url}/file/scan",
                files=files,
                timeout=60
            )
            
            if response.status_code == 200:
                scan_result = response.json()
                
                if scan_result.get('response_code') == 1:
                    # Wait for scan completion and retrieve report
                    resource = scan_result.get('resource')
                    if resource:
                        # Wait a bit for processing
                        time.sleep(15)
                        return self.get_file_report(resource)
                else:
                    return {
                        'error': f"Scan submission failed: {scan_result.get('verbose_msg', 'Unknown error')}"
                    }
            else:
                return {
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except requests.exceptions.RequestException as e:
            return {'error': f"Network error: {str(e)}"}
        except Exception as e:
            return {'error': f"Scan error: {str(e)}"}
    
    def get_file_report(self, resource: str) -> Dict[str, Any]:
        """Get file analysis report from VirusTotal
        
        Args:
            resource: File hash or scan ID
            
        Returns:
            dict: Analysis report from VirusTotal
        """
        try:
            response = self.session.get(
                f"{self.base_url}/file/report",
                params={
                    'resource': resource,
                    'apikey': self.api_key,
                    'allinfo': 1
                },
                timeout=30
            )
            
            if response.status_code == 200:
                report = response.json()
                
                if report.get('response_code') == 1:
                    # Process and format the report
                    return self._format_report(report)
                elif report.get('response_code') == 0:
                    return {
                        'error': 'File not found in VirusTotal database',
                        'resource': resource
                    }
                else:
                    return {
                        'error': f"Report retrieval failed: {report.get('verbose_msg', 'Unknown error')}"
                    }
            else:
                return {
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except requests.exceptions.RequestException as e:
            return {'error': f"Network error: {str(e)}"}
        except Exception as e:
            return {'error': f"Report retrieval error: {str(e)}"}
    
    def _format_report(self, raw_report: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal report for consistent output
        
        Args:
            raw_report: Raw report from VirusTotal API
            
        Returns:
            dict: Formatted report
        """
        try:
            scans = raw_report.get('scans', {})
            
            # Calculate detection statistics
            stats = {
                'total': len(scans),
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0
            }
            
            formatted_scans = {}
            
            for engine, result in scans.items():
                detection_result = result.get('result')
                
                if detection_result:
                    if any(malware_type in detection_result.lower() 
                          for malware_type in ['trojan', 'virus', 'malware', 'backdoor', 'rootkit']):
                        stats['malicious'] += 1
                    else:
                        stats['suspicious'] += 1
                else:
                    stats['harmless'] += 1
                
                formatted_scans[engine] = {
                    'result': detection_result or 'Clean',
                    'version': result.get('version', 'N/A'),
                    'update': result.get('update', 'N/A')
                }
            
            stats['undetected'] = stats['total'] - stats['malicious'] - stats['suspicious'] - stats['harmless']
            
            return {
                'scan_id': raw_report.get('scan_id'),
                'sha256': raw_report.get('sha256'),
                'md5': raw_report.get('md5'),
                'sha1': raw_report.get('sha1'),
                'scan_date': raw_report.get('scan_date'),
                'permalink': raw_report.get('permalink'),
                'stats': stats,
                'scans': formatted_scans,
                'total_engines': stats['total'],
                'detection_ratio': f"{stats['malicious'] + stats['suspicious']}/{stats['total']}",
                'source': 'virustotal_api'
            }
            
        except Exception as e:
            return {
                'error': f"Report formatting error: {str(e)}",
                'raw_report': raw_report
            }
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL analysis report from VirusTotal
        
        Args:
            url: URL to analyze
            
        Returns:
            dict: URL analysis report
        """
        try:
            response = self.session.get(
                f"{self.base_url}/url/report",
                params={
                    'resource': url,
                    'apikey': self.api_key,
                    'scan': 1
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            return {'error': f"URL analysis error: {str(e)}"}
    
    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get domain analysis report from VirusTotal
        
        Args:
            domain: Domain to analyze
            
        Returns:
            dict: Domain analysis report
        """
        try:
            response = self.session.get(
                f"{self.base_url}/domain/report",
                params={
                    'domain': domain,
                    'apikey': self.api_key
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            return {'error': f"Domain analysis error: {str(e)}"}
