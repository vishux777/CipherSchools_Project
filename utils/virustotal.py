"""
VirusTotal API Integration Module
Handles file scanning and report retrieval from VirusTotal
"""

import requests
import time
import hashlib
import json
import os
from datetime import datetime
import streamlit as st

class VirusTotalAPI:
    """
    VirusTotal API client for malware scanning and analysis
    """
    
    def __init__(self, api_key=None):
        """
        Initialize VirusTotal API client
        
        Args:
            api_key (str): VirusTotal API key
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def is_configured(self):
        """Check if API key is configured"""
        return bool(self.api_key and self.api_key.strip())
    
    def scan_file(self, file_data, filename):
        """
        Upload and scan a file with VirusTotal
        
        Args:
            file_data (bytes): File content as bytes
            filename (str): Name of the file
            
        Returns:
            dict: Analysis results or error information
        """
        if not self.is_configured():
            return {
                "error": "VirusTotal API key not configured",
                "status": "not_configured"
            }
        
        try:
            # Calculate file hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # First, check if file already exists in VirusTotal
            existing_report = self.get_file_report(file_hash)
            if existing_report and 'error' not in existing_report:
                existing_report['source'] = 'existing_report'
                return existing_report
            
            # Upload file for scanning
            files = {"file": (filename, file_data)}
            upload_headers = {"x-apikey": self.api_key}
            
            response = self.session.post(
                f"{self.base_url}/files",
                files=files,
                headers=upload_headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get("data", {}).get("id")
                
                if analysis_id:
                    # Wait for analysis to complete
                    return self._wait_for_analysis(analysis_id)
                else:
                    return {"error": "No analysis ID returned"}
            
            elif response.status_code == 204:
                return {
                    "error": "API quota exceeded",
                    "status": "quota_exceeded",
                    "message": "VirusTotal API quota exceeded. Please try again later."
                }
            
            elif response.status_code == 401:
                return {
                    "error": "Invalid API key",
                    "status": "unauthorized",
                    "message": "Invalid VirusTotal API key. Please check your credentials."
                }
            
            else:
                return {
                    "error": f"API request failed with status {response.status_code}",
                    "status": "request_failed",
                    "message": response.text
                }
        
        except requests.exceptions.Timeout:
            return {
                "error": "Request timeout",
                "status": "timeout",
                "message": "VirusTotal API request timed out"
            }
        
        except requests.exceptions.RequestException as e:
            return {
                "error": f"Network error: {str(e)}",
                "status": "network_error"
            }
        
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "status": "unexpected_error"
            }
    
    def get_file_report(self, file_hash):
        """
        Get analysis report for a file hash
        
        Args:
            file_hash (str): SHA256 hash of the file
            
        Returns:
            dict: Analysis report or error information
        """
        if not self.is_configured():
            return {
                "error": "VirusTotal API key not configured",
                "status": "not_configured"
            }
        
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._process_analysis_result(data)
            
            elif response.status_code == 404:
                return {
                    "error": "File not found in VirusTotal database",
                    "status": "not_found"
                }
            
            elif response.status_code == 204:
                return {
                    "error": "API quota exceeded",
                    "status": "quota_exceeded"
                }
            
            else:
                return {
                    "error": f"API request failed with status {response.status_code}",
                    "status": "request_failed"
                }
        
        except requests.exceptions.RequestException as e:
            return {
                "error": f"Network error: {str(e)}",
                "status": "network_error"
            }
        
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "status": "unexpected_error"
            }
    
    def _wait_for_analysis(self, analysis_id, max_wait_time=300):
        """
        Wait for analysis to complete
        
        Args:
            analysis_id (str): Analysis ID from VirusTotal
            max_wait_time (int): Maximum time to wait in seconds
            
        Returns:
            dict: Analysis results
        """
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            try:
                response = self.session.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status", "")
                    
                    if status == "completed":
                        # Get the file report
                        file_id = data.get("data", {}).get("attributes", {}).get("file_id")
                        if file_id:
                            return self.get_file_report(file_id)
                        else:
                            return self._process_analysis_result(data)
                    
                    elif status in ["queued", "running"]:
                        # Still processing, wait a bit
                        time.sleep(10)
                        continue
                    
                    else:
                        return {
                            "error": f"Analysis failed with status: {status}",
                            "status": "analysis_failed"
                        }
                
                else:
                    return {
                        "error": f"Failed to check analysis status: {response.status_code}",
                        "status": "status_check_failed"
                    }
            
            except Exception as e:
                return {
                    "error": f"Error while waiting for analysis: {str(e)}",
                    "status": "wait_error"
                }
        
        return {
            "error": "Analysis timeout",
            "status": "timeout",
            "message": "Analysis took too long to complete"
        }
    
    def _process_analysis_result(self, data):
        """
        Process and format VirusTotal analysis result
        
        Args:
            data (dict): Raw VirusTotal API response
            
        Returns:
            dict: Formatted analysis result
        """
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Extract scan statistics
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            
            # Format the result
            formatted_result = {
                "stats": {
                    "harmless": stats.get("harmless", 0),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0),
                    "total": sum(stats.values()) if stats else 0
                },
                "scan_date": attributes.get("last_analysis_date"),
                "scan_results": {},
                "file_info": {
                    "md5": attributes.get("md5", ""),
                    "sha1": attributes.get("sha1", ""),
                    "sha256": attributes.get("sha256", ""),
                    "size": attributes.get("size", 0),
                    "type": attributes.get("type_description", ""),
                    "names": attributes.get("names", [])
                }
            }
            
            # Process individual engine results
            for engine_name, engine_result in results.items():
                if engine_result.get("category") == "malicious":
                    formatted_result["scan_results"][engine_name] = {
                        "detected": True,
                        "result": engine_result.get("result", ""),
                        "category": engine_result.get("category", ""),
                        "engine_version": engine_result.get("engine_version", ""),
                        "engine_update": engine_result.get("engine_update", "")
                    }
            
            # Add threat assessment
            malicious_count = formatted_result["stats"]["malicious"]
            suspicious_count = formatted_result["stats"]["suspicious"]
            total_engines = formatted_result["stats"]["total"]
            
            if malicious_count > 0:
                if malicious_count >= 5:
                    threat_level = "CRITICAL"
                elif malicious_count >= 3:
                    threat_level = "HIGH"
                else:
                    threat_level = "MEDIUM"
            elif suspicious_count > 0:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            formatted_result["threat_assessment"] = {
                "level": threat_level,
                "detection_ratio": f"{malicious_count + suspicious_count}/{total_engines}",
                "confidence": "high" if malicious_count >= 3 else "medium" if malicious_count > 0 else "low"
            }
            
            return formatted_result
        
        except Exception as e:
            return {
                "error": f"Failed to process analysis result: {str(e)}",
                "status": "processing_error",
                "raw_data": data
            }
    
    def get_url_report(self, url):
        """
        Get analysis report for a URL
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Analysis report
        """
        if not self.is_configured():
            return {
                "error": "VirusTotal API key not configured",
                "status": "not_configured"
            }
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = self.session.get(
                f"{self.base_url}/urls/{url_id}",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._process_url_analysis_result(data)
            
            elif response.status_code == 404:
                return {
                    "error": "URL not found in VirusTotal database",
                    "status": "not_found"
                }
            
            else:
                return {
                    "error": f"API request failed with status {response.status_code}",
                    "status": "request_failed"
                }
        
        except Exception as e:
            return {
                "error": f"Failed to get URL report: {str(e)}",
                "status": "error"
            }
    
    def _process_url_analysis_result(self, data):
        """
        Process URL analysis result
        
        Args:
            data (dict): Raw VirusTotal API response
            
        Returns:
            dict: Formatted analysis result
        """
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "stats": stats,
                "scan_date": attributes.get("last_analysis_date"),
                "url": attributes.get("url", ""),
                "threat_assessment": {
                    "level": "HIGH" if stats.get("malicious", 0) > 0 else "LOW",
                    "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values()) if stats else 0}"
                }
            }
        
        except Exception as e:
            return {
                "error": f"Failed to process URL analysis result: {str(e)}",
                "status": "processing_error"
            }
