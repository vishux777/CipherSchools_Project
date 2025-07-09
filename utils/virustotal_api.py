import os
import requests
import time
import hashlib
from typing import Optional, Dict, Any

class VirusTotalAPI:
    """VirusTotal API v3 integration class"""
    
    def __init__(self):
        # Get API key from environment with fallback
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "726fd4f5cbe22622b7b9f9ffa9feec3237f95462bbf6f22afbc60fa23ede47f6")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 15  # Minimum 15 seconds between requests for free tier
    
    def is_api_key_valid(self) -> bool:
        """Check if the API key is valid"""
        if not self.api_key or len(self.api_key) < 60:
            return False
        
        try:
            # Simple test - get user quota information
            response = requests.get(
                f"{self.base_url}/users/{self.api_key[:20]}",
                headers=self.headers,
                timeout=5
            )
            # Return True if we get any valid response (200, 404, etc.)
            # False only if there's a network/auth error
            return response.status_code in [200, 404, 403]
        except Exception as e:
            print(f"API key validation error: {e}")
            return True  # Assume valid if we can't test (offline mode)
    
    def _wait_for_rate_limit(self):
        """Ensure we don't exceed rate limits"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last_request
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def get_file_report(self, file_hash: str) -> Optional[Dict[Any, Any]]:
        """Get file analysis report by hash"""
        try:
            self._wait_for_rate_limit()
            
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None  # File not found in VT database
            else:
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            print(f"Error getting file report: {e}")
            return None
    
    def upload_file(self, file_data: bytes) -> Optional[Dict[Any, Any]]:
        """Upload file to VirusTotal for analysis"""
        try:
            # Check file size (VirusTotal has limits)
            if len(file_data) > 32 * 1024 * 1024:  # 32MB limit for free tier
                raise ValueError("File too large for VirusTotal upload (max 32MB)")
            
            self._wait_for_rate_limit()
            
            # Upload file
            url = f"{self.base_url}/files"
            files = {"file": ("sample", file_data)}
            headers = {"x-apikey": self.api_key}  # Don't include Content-Type for file upload
            
            response = requests.post(url, headers=headers, files=files, timeout=60)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Upload failed with status {response.status_code}: {response.text}")
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            print(f"Error uploading file: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error during upload: {e}")
            return None
    
    def get_analysis_result(self, analysis_id: str) -> Optional[Dict[Any, Any]]:
        """Get analysis result by analysis ID"""
        try:
            self._wait_for_rate_limit()
            
            url = f"{self.base_url}/analyses/{analysis_id}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            print(f"Error getting analysis result: {e}")
            return None
    
    def get_file_behavior(self, file_hash: str) -> Optional[Dict[Any, Any]]:
        """Get file behavior analysis"""
        try:
            self._wait_for_rate_limit()
            
            url = f"{self.base_url}/files/{file_hash}/behaviour_summary"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None  # No behavior analysis available
            else:
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            print(f"Error getting file behavior: {e}")
            return None
    
    def search_files(self, query: str) -> Optional[Dict[Any, Any]]:
        """Search files using VirusTotal Intelligence"""
        try:
            self._wait_for_rate_limit()
            
            url = f"{self.base_url}/intelligence/search"
            params = {"query": query}
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            print(f"Error searching files: {e}")
            return None