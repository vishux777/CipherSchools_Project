"""
VirusTotal API Integration Module

Enhanced VirusTotal API client with robust error handling,
rate limiting, and comprehensive result processing.
"""

import requests
import time
import hashlib
import json
import os
import base64
from datetime import datetime
import streamlit as st

class VirusTotalAPI:
    """
    Enhanced VirusTotal API client for malware scanning and analysis
    """
    
    def __init__(self, api_key=None):
        """
        Initialize VirusTotal API client with enhanced configuration
        
        Args:
            api_key (str): VirusTotal API key
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Rate limiting configuration
        self.last_request_time = 0
        self.min_request_interval = 15  # 15 seconds for free tier (4 requests/minute)
        
        # Request timeout configuration
        self.timeout = 30
        
        # Maximum file size (32MB for free accounts)
        self.max_file_size = 32 * 1024 * 1024
    
    def is_configured(self):
        """Check if API key is properly configured"""
        return bool(self.api_key and self.api_key.strip() and len(self.api_key.strip()) >= 64)
    
    def _rate_limit(self):
        """Implement rate limiting to avoid API quota issues"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _handle_response(self, response):
        """
        Enhanced response handling with detailed error messages
        
        Args:
            response: requests.Response object
            
        Returns:
            dict: Processed response data or error information
        """
        if response.status_code == 200:
            try:
                return response.json()
            except json.JSONDecodeError:
                return {
                    "error": "Invalid JSON response from VirusTotal",
                    "status": "json_error",
                    "raw_response": response.text[:500]
                }
        
        elif response.status_code == 204:
            return {
                "error": "API quota exceeded - too many requests",
                "status": "quota_exceeded",
                "message": "You have exceeded the VirusTotal API rate limit. Please wait before making more requests.",
                "retry_after": response.headers.get("Retry-After", "300")
            }
        
        elif response.status_code == 400:
            return {
                "error": "Bad request - invalid parameters",
                "status": "bad_request",
                "message": "The request was invalid. Please check your file or parameters."
            }
        
        elif response.status_code == 401:
            return {
                "error": "Authentication failed - invalid API key",
                "status": "unauthorized",
                "message": "Your VirusTotal API key is invalid or expired. Please check your credentials."
            }
        
        elif response.status_code == 403:
            return {
                "error": "Access forbidden",
                "status": "forbidden",
                "message": "Your API key doesn't have permission for this operation."
            }
        
        elif response.status_code == 404:
            return {
                "error": "Resource not found",
                "status": "not_found",
                "message": "The requested file or resource was not found in VirusTotal database."
            }
        
        elif response.status_code == 413:
            return {
                "error": "File too large",
                "status": "file_too_large",
                "message": f"File exceeds the maximum size limit of {self.max_file_size / (1024*1024):.0f}MB."
            }
        
        elif response.status_code == 429:
            return {
                "error": "Too many requests",
                "status": "rate_limited",
                "message": "Rate limit exceeded. Please wait before making more requests.",
                "retry_after": response.headers.get("Retry-After", "300")
            }
        
        else:
            return {
                "error": f"HTTP {response.status_code} - {response.reason}",
                "status": "http_error",
                "message": f"Unexpected response from VirusTotal: {response.status_code}",
                "response_text": response.text[:500]
            }
    
    def scan_file(self, file_data, filename):
        """
        Upload and scan a file with VirusTotal with enhanced error handling
        
        Args:
            file_data (bytes): File content as bytes
            filename (str): Name of the file
            
        Returns:
            dict: Analysis results or detailed error information
        """
        if not self.is_configured():
            return {
                "error": "VirusTotal API key not configured",
                "status": "not_configured",
                "message": "Please provide a valid VirusTotal API key to use this feature."
            }
        
        # Check file size
        if len(file_data) > self.max_file_size:
            return {
                "error": "File too large for VirusTotal",
                "status": "file_too_large",
                "message": f"File size ({len(file_data)} bytes) exceeds VirusTotal limit of {self.max_file_size} bytes."
            }
        
        try:
            # Calculate file hash first
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Check if file already exists in VirusTotal
            st.info("🔍 Checking if file exists in VirusTotal database...")
            existing_report = self.get_file_report(file_hash)
            
            if existing_report and 'error' not in existing_report:
                st.success("✅ File found in database - retrieving existing analysis")
                existing_report['source'] = 'existing_report'
                existing_report['scan_type'] = 'cached'
                return existing_report
            
            # Rate limiting before upload
            self._rate_limit()
            
            # Upload file for scanning
            st.info("📤 Uploading file to VirusTotal for analysis...")
            
            files = {"file": (filename, file_data, "application/octet-stream")}
            upload_headers = {"x-apikey": self.api_key}
            
            response = self.session.post(
                f"{self.base_url}/files",
                files=files,
                headers=upload_headers,
                timeout=self.timeout
            )
            
            result = self._handle_response(response)
            
            if 'error' in result:
                return result
            
            # Extract analysis ID
            analysis_id = result.get("data", {}).get("id")
            if not analysis_id:
                return {
                    "error": "No analysis ID returned from VirusTotal",
                    "status": "no_analysis_id",
                    "raw_response": result
                }
            
            st.info("⏳ File uploaded successfully. Waiting for analysis to complete...")
            
            # Wait for analysis to complete
            analysis_result = self._wait_for_analysis(analysis_id)
            analysis_result['source'] = 'new_upload'
            analysis_result['scan_type'] = 'fresh'
            
            return analysis_result
            
        except requests.exceptions.Timeout:
            return {
                "error": "Request timeout",
                "status": "timeout",
                "message": "The request to VirusTotal timed out. Please try again later."
            }
        
        except requests.exceptions.ConnectionError:
            return {
                "error": "Connection error",
                "status": "connection_error",
                "message": "Failed to connect to VirusTotal. Please check your internet connection."
            }
        
        except requests.exceptions.RequestException as e:
            return {
                "error": f"Network error: {str(e)}",
                "status": "network_error",
                "message": "A network error occurred while communicating with VirusTotal."
            }
        
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "status": "unexpected_error",
                "message": "An unexpected error occurred during file scanning."
            }
    
    def get_file_report(self, file_hash):
        """
        Get analysis report for a file hash with enhanced processing
        
        Args:
            file_hash (str): SHA256, SHA1, or MD5 hash of the file
            
        Returns:
            dict: Analysis report or error information
        """
        if not self.is_configured():
            return {
                "error": "VirusTotal API key not configured",
                "status": "not_configured"
            }
        
        try:
            # Rate limiting
            self._rate_limit()
            
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}",
                timeout=self.timeout
            )
            
            result = self._handle_response(response)
            
            if 'error' in result:
                return result
            
            # Process the analysis result
            return self._process_analysis_result(result)
            
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
    
    def _wait_for_analysis(self, analysis_id, max_wait_time=600):
        """
        Wait for analysis to complete with enhanced progress tracking
        
        Args:
            analysis_id (str): Analysis ID from VirusTotal
            max_wait_time (int): Maximum time to wait in seconds
            
        Returns:
            dict: Analysis results
        """
        start_time = time.time()
        check_interval = 10  # Check every 10 seconds
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        while time.time() - start_time < max_wait_time:
            try:
                # Rate limiting
                self._rate_limit()
                
                response = self.session.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    timeout=self.timeout
                )
                
                result = self._handle_response(response)
                
                if 'error' in result:
                    progress_bar.empty()
                    status_text.empty()
                    return result
                
                # Extract status
                attributes = result.get("data", {}).get("attributes", {})
                status = attributes.get("status", "unknown")
                
                # Update progress
                elapsed_time = time.time() - start_time
                progress = min(elapsed_time / max_wait_time, 0.9)
                progress_bar.progress(progress)
                status_text.text(f"Analysis status: {status.upper()} - Elapsed: {elapsed_time:.0f}s")
                
                if status == "completed":
                    progress_bar.progress(1.0)
                    status_text.text("✅ Analysis completed successfully!")
                    
                    # Get the final report
                    stats = attributes.get("stats", {})
                    if stats:
                        # Use the analysis result directly
                        processed_result = self._process_analysis_attributes(attributes)
                        progress_bar.empty()
                        status_text.empty()
                        return processed_result
                    else:
                        # Fallback to file report if no stats in analysis
                        file_info = attributes.get("file_info", {})
                        if file_info and file_info.get("sha256"):
                            file_report = self.get_file_report(file_info["sha256"])
                            progress_bar.empty()
                            status_text.empty()
                            return file_report
                
                elif status in ["queued", "running"]:
                    # Still processing
                    time.sleep(check_interval)
                    continue
                
                else:
                    progress_bar.empty()
                    status_text.empty()
                    return {
                        "error": f"Analysis failed with status: {status}",
                        "status": "analysis_failed",
                        "analysis_status": status
                    }
                
            except Exception as e:
                progress_bar.empty()
                status_text.empty()
                return {
                    "error": f"Error while waiting for analysis: {str(e)}",
                    "status": "wait_error"
                }
        
        progress_bar.empty()
        status_text.empty()
        return {
            "error": "Analysis timeout - taking longer than expected",
            "status": "timeout",
            "message": f"Analysis took longer than {max_wait_time} seconds to complete"
        }
    
    def _process_analysis_result(self, data):
        """
        Process and format VirusTotal analysis result with enhanced data extraction
        
        Args:
            data (dict): Raw VirusTotal API response
            
        Returns:
            dict: Formatted analysis result
        """
        try:
            attributes = data.get("data", {}).get("attributes", {})
            return self._process_analysis_attributes(attributes)
            
        except Exception as e:
            return {
                "error": f"Failed to process analysis result: {str(e)}",
                "status": "processing_error",
                "raw_data": data
            }
    
    def _process_analysis_attributes(self, attributes):
        """
        Process VirusTotal attributes into standardized format
        
        Args:
            attributes (dict): VirusTotal attributes
            
        Returns:
            dict: Formatted analysis result
        """
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
                "names": attributes.get("names", []),
                "first_submission_date": attributes.get("first_submission_date"),
                "last_submission_date": attributes.get("last_submission_date"),
                "times_submitted": attributes.get("times_submitted", 0)
            },
            "community_info": {
                "reputation": attributes.get("reputation", 0),
                "votes": attributes.get("total_votes", {}),
                "comments": attributes.get("comments", [])
            }
        }
        
        # Process individual engine results
        detections = {}
        for engine_name, engine_result in results.items():
            category = engine_result.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections[engine_name] = {
                    "detected": True,
                    "result": engine_result.get("result", ""),
                    "category": category,
                    "engine_version": engine_result.get("engine_version", ""),
                    "engine_update": engine_result.get("engine_update", ""),
                    "method": engine_result.get("method", "")
                }
        
        formatted_result["scan_results"] = detections
        
        # Enhanced threat assessment
        malicious_count = formatted_result["stats"]["malicious"]
        suspicious_count = formatted_result["stats"]["suspicious"]
        total_engines = formatted_result["stats"]["total"]
        
        # Determine threat level based on detection ratio
        detection_ratio = (malicious_count + suspicious_count) / max(total_engines, 1)
        
        if malicious_count >= 5:
            threat_level = "CRITICAL"
            confidence = "very_high"
        elif malicious_count >= 3:
            threat_level = "HIGH" 
            confidence = "high"
        elif malicious_count >= 1:
            threat_level = "MEDIUM"
            confidence = "medium"
        elif suspicious_count >= 3:
            threat_level = "MEDIUM"
            confidence = "medium"
        elif suspicious_count >= 1:
            threat_level = "LOW"
            confidence = "low"
        else:
            threat_level = "CLEAN"
            confidence = "high"
        
        formatted_result["threat_assessment"] = {
            "level": threat_level,
            "detection_ratio": f"{malicious_count + suspicious_count}/{total_engines}",
            "detection_percentage": f"{detection_ratio * 100:.1f}%",
            "confidence": confidence,
            "malicious_engines": malicious_count,
            "suspicious_engines": suspicious_count,
            "clean_engines": formatted_result["stats"]["harmless"] + formatted_result["stats"]["undetected"]
        }
        
        return formatted_result
    
    def scan_url(self, url):
        """
        Submit URL for analysis
        
        Args:
            url (str): URL to scan
            
        Returns:
            dict: Analysis result
        """
        if not self.is_configured():
            return {
                "error": "VirusTotal API key not configured",
                "status": "not_configured"
            }
        
        try:
            self._rate_limit()
            
            # Submit URL for analysis
            data = {"url": url}
            response = self.session.post(
                f"{self.base_url}/urls",
                data=data,
                timeout=self.timeout
            )
            
            result = self._handle_response(response)
            
            if 'error' in result:
                return result
            
            # Get analysis ID and wait for completion
            analysis_id = result.get("data", {}).get("id")
            if analysis_id:
                return self._wait_for_analysis(analysis_id)
            else:
                return {"error": "No analysis ID returned for URL scan"}
                
        except Exception as e:
            return {
                "error": f"Failed to scan URL: {str(e)}",
                "status": "error"
            }
    
    def get_api_usage(self):
        """
        Get current API usage statistics (if available)
        
        Returns:
            dict: API usage information
        """
        if not self.is_configured():
            return {"error": "API key not configured"}
        
        try:
            self._rate_limit()
            
            response = self.session.get(
                f"{self.base_url}/users/{self.api_key}/overall_quotas",
                timeout=self.timeout
            )
            
            return self._handle_response(response)
            
        except Exception as e:
            return {
                "error": f"Failed to get API usage: {str(e)}",
                "status": "error"
            }
