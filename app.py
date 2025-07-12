"""
MalwareShield Pro - Advanced Malware Detection Tool

A comprehensive Streamlit-based malware detection application with VirusTotal integration,
entropy analysis, pattern detection, and professional reporting capabilities.
"""

import streamlit as st
import os
import hashlib
import time
import re
import io
import math
import string
import json
import base64
from datetime import datetime
from collections import Counter
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Import utility modules with proper error handling
try:
    from utils.virustotal import VirusTotalAPI
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import VirusTotal module: {e}")
    # Fallback implementation
    class VirusTotalAPI:
        def __init__(self, api_key):
            self.api_key = api_key
        
        def is_configured(self):
            return bool(self.api_key)
        
        def scan_file(self, file_data, filename):
            return {"error": "VirusTotal module not available - check installation"}
        
        def get_file_report(self, file_hash):
            return {"error": "VirusTotal module not available - check installation"}

try:
    from utils.analysis_engine import AnalysisEngine
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import Analysis Engine: {e}")
    class AnalysisEngine:
        def analyze_file(self, file_data, filename, config):
            return {"error": "Analysis engine not available - check installation"}

try:
    from utils.report_generator import ReportGenerator
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import Report Generator: {e}")
    class ReportGenerator:
        def generate_report(self, results):
            return {"error": "Report generator not available - check installation"}
        
        def export_json(self, results):
            return json.dumps(results, indent=2, default=str)

try:
    from utils.threat_scorer import ThreatScorer
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import Threat Scorer: {e}")
    class ThreatScorer:
        def calculate_score(self, analysis_data):
            return {"score": 0, "level": "UNKNOWN", "reasons": ["Threat scorer not available"]}

# Configure page with dark theme
st.set_page_config(
    page_title="🛡️ MalwareShield Pro - Advanced Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark theme CSS - Professional cybersecurity styling
st.markdown("""
<style>
    /* Main application styling */
    .main {
        background-color: #0e1117;
        color: #fafafa;
    }
    
    .stApp {
        background-color: #0e1117;
    }
    
    /* Sidebar styling */
    .css-1d391kg, .css-1544g2n {
        background-color: #262730;
    }
    
    /* Alert and notification styling */
    .stAlert {
        background-color: #262730;
        border: 1px solid #444;
        color: #fafafa;
    }
    
    /* Threat level banners */
    .threat-critical {
        background: linear-gradient(135deg, #8B0000, #DC143C);
        padding: 20px;
        border-radius: 12px;
        color: white;
        font-weight: bold;
        text-align: center;
        margin: 15px 0;
        box-shadow: 0 4px 8px rgba(220, 20, 60, 0.3);
        border: 2px solid #FF1744;
    }
    
    .threat-high {
        background: linear-gradient(135deg, #FF4500, #FF6347);
        padding: 20px;
        border-radius: 12px;
        color: white;
        font-weight: bold;
        text-align: center;
        margin: 15px 0;
        box-shadow: 0 4px 8px rgba(255, 99, 71, 0.3);
        border: 2px solid #FF5722;
    }
    
    .threat-medium {
        background: linear-gradient(135deg, #FF8C00, #FFA500);
        padding: 20px;
        border-radius: 12px;
        color: white;
        font-weight: bold;
        text-align: center;
        margin: 15px 0;
        box-shadow: 0 4px 8px rgba(255, 165, 0, 0.3);
        border: 2px solid #FF9800;
    }
    
    .threat-low {
        background: linear-gradient(135deg, #228B22, #32CD32);
        padding: 20px;
        border-radius: 12px;
        color: white;
        font-weight: bold;
        text-align: center;
        margin: 15px 0;
        box-shadow: 0 4px 8px rgba(50, 205, 50, 0.3);
        border: 2px solid #4CAF50;
    }
    
    .threat-clean {
        background: linear-gradient(135deg, #228B22, #32CD32);
        padding: 20px;
        border-radius: 12px;
        color: white;
        font-weight: bold;
        text-align: center;
        margin: 15px 0;
        box-shadow: 0 4px 8px rgba(50, 205, 50, 0.3);
        border: 2px solid #4CAF50;
    }
    
    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #262730, #1a1d29);
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #444;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }
    
    .metric-card h4 {
        color: #00aaff;
        margin: 0 0 10px 0;
        font-size: 1.1em;
    }
    
    /* Status indicators */
    .scan-status {
        background: linear-gradient(135deg, #1a1d29, #0f1419);
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #00ff88;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0, 255, 136, 0.1);
    }
    
    .error-box {
        background: linear-gradient(135deg, #2d1b1b, #1f1212);
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #ff4444;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(255, 68, 68, 0.1);
    }
    
    .info-box {
        background: linear-gradient(135deg, #1b2d3a, #12232e);
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #4444ff;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(68, 68, 255, 0.1);
    }
    
    .warning-box {
        background: linear-gradient(135deg, #3a2d1b, #2e2312);
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #ffaa44;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(255, 170, 68, 0.1);
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #262730, #1a1d29);
        border: 1px solid #444;
        color: #fafafa;
        border-radius: 8px;
        padding: 0.5em 1em;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #1a1d29, #262730);
        border-color: #00aaff;
        box-shadow: 0 2px 8px rgba(0, 170, 255, 0.2);
    }
    
    /* File uploader styling */
    .stFileUploader {
        background-color: #262730;
        border: 2px dashed #444;
        border-radius: 10px;
        padding: 20px;
    }
    
    /* Progress bar styling */
    .stProgress > div > div {
        background: linear-gradient(90deg, #00aaff, #0088cc);
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: #262730;
        border: 1px solid #444;
    }
    
    /* Table styling */
    .dataframe {
        background-color: #262730;
        color: #fafafa;
    }
    
    /* Text input styling */
    .stTextInput > div > div > input {
        background-color: #262730;
        color: #fafafa;
        border: 1px solid #444;
    }
    
    /* Select box styling */
    .stSelectbox > div > div {
        background-color: #262730;
        color: #fafafa;
    }
    
    /* Metric styling */
    .metric-container {
        background: linear-gradient(135deg, #262730, #1a1d29);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #444;
        margin: 5px 0;
    }
    
    /* Professional header styling */
    .main-header {
        background: linear-gradient(135deg, #1a1d29, #0e1117);
        padding: 30px 20px;
        border-radius: 15px;
        border: 1px solid #444;
        margin-bottom: 30px;
        text-align: center;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
    }
    
    /* Footer styling */
    .footer {
        text-align: center;
        padding: 20px;
        color: #888;
        border-top: 1px solid #444;
        margin-top: 40px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
def init_session_state():
    """Initialize session state variables"""
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'uploaded_file' not in st.session_state:
        st.session_state.uploaded_file = None
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    if 'vt_api_key' not in st.session_state:
        st.session_state.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def calculate_file_hashes(file_data):
    """Calculate various hashes for the file"""
    hashes = {}
    hashes['md5'] = hashlib.md5(file_data).hexdigest()
    hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
    hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
    return hashes

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    # Count frequency of each byte
    frequency = Counter(data)
    data_len = len(data)
    
    # Calculate entropy
    entropy = 0
    for count in frequency.values():
        p = count / data_len
        entropy -= p * math.log2(p)
    
    return entropy

def extract_strings(file_data, min_length=4, max_count=100):
    """Extract printable strings from file data"""
    strings = []
    current_string = ""
    
    for byte in file_data:
        char = chr(byte) if byte < 128 else ''
        if char in string.printable and char not in '\t\n\r\x0b\x0c':
            current_string += char
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
                if len(strings) >= max_count:
                    break
            current_string = ""
    
    # Add final string if valid
    if len(current_string) >= min_length and len(strings) < max_count:
        strings.append(current_string)
    
    return strings

def detect_patterns(file_data, strings_list):
    """Detect suspicious patterns in file"""
    patterns = {
        'urls': re.compile(r'https?://[^\s<>"]+'),
        'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'ips': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'suspicious_apis': re.compile(r'\b(CreateFile|WriteFile|RegCreateKey|RegSetValue|GetProcAddress|LoadLibrary|VirtualAlloc|CreateProcess|ShellExecute)\b', re.IGNORECASE),
        'crypto_indicators': re.compile(r'\b(bitcoin|btc|wallet|private[_\s]?key|encryption|decrypt|cipher)\b', re.IGNORECASE),
        'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^\\]+', re.IGNORECASE),
        'file_paths': re.compile(r'[A-Za-z]:\\\\[^\\]+(?:\\\\[^\\]+)*', re.IGNORECASE),
        'bitcoin_addresses': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        'ethereum_addresses': re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    }
    
    detected = {}
    file_string = ' '.join(strings_list)
    
    for pattern_name, pattern in patterns.items():
        matches = pattern.findall(file_string)
        if matches:
            detected[pattern_name] = list(set(matches))  # Remove duplicates
    
    return detected

def display_threat_banner(threat_level, threat_score):
    """Display threat level banner with appropriate styling"""
    threat_class = f"threat-{threat_level.lower()}"
    
    if threat_level == "CRITICAL":
        icon = "🚨"
        message = f"CRITICAL THREAT DETECTED - Score: {threat_score}/100"
    elif threat_level == "HIGH":
        icon = "⚠️"
        message = f"HIGH THREAT DETECTED - Score: {threat_score}/100"
    elif threat_level == "MEDIUM":
        icon = "⚡"
        message = f"MEDIUM THREAT DETECTED - Score: {threat_score}/100"
    elif threat_level == "LOW":
        icon = "🔍"
        message = f"LOW THREAT LEVEL - Score: {threat_score}/100"
    else:  # CLEAN
        icon = "✅"
        message = f"FILE APPEARS CLEAN - Score: {threat_score}/100"
    
    st.markdown(f"""
    <div class="{threat_class}">
        {icon} {message}
    </div>
    """, unsafe_allow_html=True)

def display_system_status():
    """Display real-time system status indicators"""
    st.markdown("### 🖥️ System Status")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h4>🔧 Analysis Engine</h4>
            <p style="color: #00ff88;">● Online</p>
            <small>Ready for analysis</small>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        vt_status = "Connected" if st.session_state.vt_api_key else "Offline"
        vt_color = "#00ff88" if st.session_state.vt_api_key else "#ff4444"
        vt_icon = "🌐" if st.session_state.vt_api_key else "❌"
        
        st.markdown(f"""
        <div class="metric-card">
            <h4>{vt_icon} VirusTotal</h4>
            <p style="color: {vt_color};">● {vt_status}</p>
            <small>{"API Active" if st.session_state.vt_api_key else "No API Key"}</small>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        scan_count = len(st.session_state.scan_history)
        st.markdown(f"""
        <div class="metric-card">
            <h4>📊 Session Scans</h4>
            <p style="color: #00aaff;">● {scan_count}</p>
            <small>Files analyzed</small>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        threat_count = sum(1 for scan in st.session_state.scan_history 
                          if scan.get('threat_detected', False))
        threat_color = "#ff4444" if threat_count > 0 else "#00ff88"
        
        st.markdown(f"""
        <div class="metric-card">
            <h4>⚠️ Threats Detected</h4>
            <p style="color: {threat_color};">● {threat_count}</p>
            <small>This Session</small>
        </div>
        """, unsafe_allow_html=True)

def display_file_info(uploaded_file):
    """Display enhanced file information"""
    file_size = len(uploaded_file.getvalue())
    file_type = uploaded_file.type or 'Unknown'
    
    st.markdown("### 📄 File Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"""
        <div class="info-box">
            <p><strong>📝 Name:</strong> {uploaded_file.name}</p>
            <p><strong>📏 Size:</strong> {format_file_size(file_size)}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="info-box">
            <p><strong>🏷️ Type:</strong> {file_type}</p>
            <p><strong>⏰ Uploaded:</strong> {datetime.now().strftime('%H:%M:%S')}</p>
        </div>
        """, unsafe_allow_html=True)

def display_virustotal_results(vt_results):
    """Display VirusTotal scan results with enhanced visualization"""
    if 'error' in vt_results:
        error_msg = vt_results['error']
        status = vt_results.get('status', '')
        message = vt_results.get('message', '')
        
        st.markdown(f"""
        <div class="error-box">
            <h4>❌ VirusTotal Error</h4>
            <p><strong>Error:</strong> {error_msg}</p>
            {f'<p><strong>Status:</strong> {status}</p>' if status else ''}
            {f'<p><strong>Details:</strong> {message}</p>' if message else ''}
        </div>
        """, unsafe_allow_html=True)
        return
    
    st.markdown("### 🌍 VirusTotal Analysis Results")
    
    stats = vt_results.get('stats', {})
    if not stats:
        st.warning("⚠️ No VirusTotal statistics available")
        return
    
    # Create metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        malicious = stats.get('malicious', 0)
        color = "#ff4444" if malicious > 0 else "#00ff88"
        st.markdown(f"""
        <div class="metric-card">
            <h4>🦠 Malicious</h4>
            <p style="color: {color}; font-size: 1.5em;">{malicious}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        suspicious = stats.get('suspicious', 0)
        color = "#ffaa44" if suspicious > 0 else "#00ff88"
        st.markdown(f"""
        <div class="metric-card">
            <h4>⚠️ Suspicious</h4>
            <p style="color: {color}; font-size: 1.5em;">{suspicious}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        harmless = stats.get('harmless', 0)
        st.markdown(f"""
        <div class="metric-card">
            <h4>✅ Clean</h4>
            <p style="color: #00ff88; font-size: 1.5em;">{harmless}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        total = stats.get('total', 0)
        st.markdown(f"""
        <div class="metric-card">
            <h4>🔧 Total Engines</h4>
            <p style="color: #00aaff; font-size: 1.5em;">{total}</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Create visualization if we have data
    if total > 0:
        # Pie chart for detection distribution
        labels = []
        values = []
        colors = []
        
        if malicious > 0:
            labels.append(f"Malicious ({malicious})")
            values.append(malicious)
            colors.append('#ff4444')
        
        if suspicious > 0:
            labels.append(f"Suspicious ({suspicious})")
            values.append(suspicious)
            colors.append('#ffaa44')
        
        if harmless > 0:
            labels.append(f"Clean ({harmless})")
            values.append(harmless)
            colors.append('#00ff88')
        
        undetected = stats.get('undetected', 0)
        if undetected > 0:
            labels.append(f"Undetected ({undetected})")
            values.append(undetected)
            colors.append('#888888')
        
        if values:
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                marker_colors=colors,
                hole=0.4,
                textfont=dict(color='white')
            )])
            
            fig.update_layout(
                title={
                    'text': "VirusTotal Detection Results",
                    'font': {'color': 'white', 'size': 16}
                },
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='white',
                showlegend=True,
                legend=dict(
                    font=dict(color='white'),
                    bgcolor='rgba(0,0,0,0)'
                )
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    # Display detailed detection results
    scan_results = vt_results.get('scan_results', {})
    if scan_results:
        st.markdown("#### 🔍 Detection Details")
        
        # Show first 10 detections in an expandable section
        with st.expander(f"View Detections ({len(scan_results)} engines detected threats)", expanded=False):
            for i, (engine, result) in enumerate(list(scan_results.items())[:15]):
                threat_name = result.get('result', 'Unknown')
                category = result.get('category', 'unknown')
                
                color = "#ff4444" if category == "malicious" else "#ffaa44"
                
                st.markdown(f"""
                <div class="error-box" style="margin: 5px 0; padding: 10px;">
                    <strong style="color: {color};">{engine}:</strong> {threat_name}
                    <br><small>Category: {category.title()}</small>
                </div>
                """, unsafe_allow_html=True)
            
            if len(scan_results) > 15:
                st.info(f"Showing 15 of {len(scan_results)} detections")

def display_analysis_results(results):
    """Display comprehensive analysis results with enhanced visualization"""
    st.markdown("## 📊 Comprehensive Analysis Results")
    
    # Threat Assessment Banner
    threat_assessment = results.get('threat_assessment', {})
    threat_level = threat_assessment.get('level', 'UNKNOWN')
    threat_score = threat_assessment.get('score', 0)
    threat_reasons = threat_assessment.get('reasons', [])
    
    # Display threat banner
    display_threat_banner(threat_level, threat_score)
    
    # Threat Score Gauge
    if threat_score > 0:
        st.markdown("### 📈 Threat Score Analysis")
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=threat_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Threat Score", 'font': {'color': 'white', 'size': 20}},
            delta={'reference': 50, 'increasing': {'color': "#ff4444"}, 'decreasing': {'color': "#00ff88"}},
            gauge={
                'axis': {'range': [None, 100], 'tickfont': {'color': 'white'}},
                'bar': {'color': "#00aaff"},
                'steps': [
                    {'range': [0, 15], 'color': "darkgreen"},
                    {'range': [15, 35], 'color': "green"},
                    {'range': [35, 60], 'color': "orange"},
                    {'range': [60, 85], 'color': "red"},
                    {'range': [85, 100], 'color': "darkred"}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        fig.update_layout(
            height=300,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Display threat reasons
    if threat_reasons:
        st.markdown("### ⚠️ Threat Indicators")
        for i, reason in enumerate(threat_reasons, 1):
            st.markdown(f"""
            <div class="warning-box">
                <strong>{i}.</strong> {reason}
            </div>
            """, unsafe_allow_html=True)
    
    # File Hashes Section
    if 'hashes' in results:
        st.markdown("### 🔍 File Hashes")
        hashes = results['hashes']
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.text_input("MD5", hashes.get('md5', ''), disabled=True)
        with col2:
            st.text_input("SHA1", hashes.get('sha1', ''), disabled=True)
        with col3:
            st.text_input("SHA256", hashes.get('sha256', ''), disabled=True)
    
    # Entropy Analysis
    if 'entropy' in results:
        st.markdown("### 📈 Entropy Analysis")
        entropy_data = results['entropy']
        
        if isinstance(entropy_data, dict):
            entropy_value = entropy_data.get('overall_entropy', 0)
            
            # Create entropy visualization
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=entropy_value,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "File Entropy", 'font': {'color': 'white'}},
                gauge={
                    'axis': {'range': [None, 8], 'tickfont': {'color': 'white'}},
                    'bar': {'color': "#00aaff"},
                    'steps': [
                        {'range': [0, 4], 'color': "darkgreen"},
                        {'range': [4, 6], 'color': "yellow"},
                        {'range': [6, 7.5], 'color': "orange"},
                        {'range': [7.5, 8], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 7.5
                    }
                }
            ))
            
            fig.update_layout(
                height=300,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Entropy interpretation
            if entropy_value > 7.5:
                st.markdown("""
                <div class="error-box">
                    ⚠️ <strong>High entropy detected</strong> - File may be encrypted, packed, or contain random data
                </div>
                """, unsafe_allow_html=True)
            elif entropy_value > 6.5:
                st.markdown("""
                <div class="warning-box">
                    ⚡ <strong>Moderate entropy</strong> - File contains mixed content types
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="scan-status">
                    ✅ <strong>Normal entropy</strong> - File appears to contain typical structured data
                </div>
                """, unsafe_allow_html=True)
        else:
            # Handle legacy entropy format
            entropy_value = entropy_data if isinstance(entropy_data, (int, float)) else 0
            st.metric("Entropy Value", f"{entropy_value:.2f}")
    
    # Patterns Detection
    if 'patterns' in results and results['patterns']:
        st.markdown("### 🎯 Suspicious Pattern Detection")
        
        patterns = results['patterns']
        pattern_count = sum(len(matches) for matches in patterns.values() if matches)
        
        if pattern_count > 0:
            st.markdown(f"**Found {pattern_count} suspicious patterns across {len(patterns)} categories**")
            
            # Create tabs for different pattern types
            pattern_tabs = st.tabs(["🔗 Network", "💰 Crypto", "🔧 APIs", "📁 Files", "🔍 Other"])
            
            network_patterns = ['urls', 'emails', 'ip_addresses']
            crypto_patterns = ['bitcoin_addresses', 'ethereum_addresses', 'crypto_indicators']
            api_patterns = [k for k in patterns.keys() if k.startswith('api_') or 'api' in k]
            file_patterns = ['file_paths', 'registry_keys']
            other_patterns = [k for k in patterns.keys() if k not in network_patterns + crypto_patterns + api_patterns + file_patterns]
            
            with pattern_tabs[0]:  # Network
                _display_pattern_category(patterns, network_patterns, "Network-related patterns")
            
            with pattern_tabs[1]:  # Crypto
                _display_pattern_category(patterns, crypto_patterns, "Cryptocurrency-related patterns")
            
            with pattern_tabs[2]:  # APIs
                _display_pattern_category(patterns, api_patterns, "API and system call patterns")
            
            with pattern_tabs[3]:  # Files
                _display_pattern_category(patterns, file_patterns, "File and registry patterns")
            
            with pattern_tabs[4]:  # Other
                _display_pattern_category(patterns, other_patterns, "Other suspicious patterns")
    
    # String Analysis
    if 'strings' in results and results['strings']:
        st.markdown("### 📝 String Analysis")
        strings_data = results['strings']
        
        if isinstance(strings_data, dict):
            ascii_count = strings_data.get('total_ascii', 0)
            unicode_count = strings_data.get('total_unicode', 0)
            total_strings = ascii_count + unicode_count
            
            if total_strings > 0:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("ASCII Strings", ascii_count)
                with col2:
                    st.metric("Unicode Strings", unicode_count)
                with col3:
                    st.metric("Total Strings", total_strings)
                
                # Show sample strings
                all_strings = strings_data.get('combined', [])
                if all_strings:
                    with st.expander(f"📋 Sample Strings (showing first 20 of {len(all_strings)})"):
                        sample_strings = all_strings[:20]
                        for i, s in enumerate(sample_strings, 1):
                            st.code(f"{i:2d}. {s}")
        
        elif isinstance(strings_data, list) and strings_data:
            st.metric("Extracted Strings", len(strings_data))
            with st.expander(f"📋 Sample Strings (showing first 20 of {len(strings_data)})"):
                for i, s in enumerate(strings_data[:20], 1):
                    st.code(f"{i:2d}. {s}")
    
    # VirusTotal Results
    if 'virustotal' in results:
        display_virustotal_results(results['virustotal'])
    
    # Component Scores (if available from threat scorer)
    if 'component_scores' in threat_assessment:
        st.markdown("### 🔬 Analysis Component Breakdown")
        component_scores = threat_assessment['component_scores']
        
        # Create a bar chart of component scores
        components = list(component_scores.keys())
        scores = list(component_scores.values())
        
        fig = go.Figure(data=[
            go.Bar(
                x=components,
                y=scores,
                marker_color=['#ff4444' if s > 70 else '#ffaa44' if s > 40 else '#00ff88' for s in scores],
                text=[f"{s:.1f}" for s in scores],
                textposition='auto',
            )
        ])
        
        fig.update_layout(
            title={'text': "Component Analysis Scores", 'font': {'color': 'white'}},
            xaxis={'title': 'Analysis Components', 'tickfont': {'color': 'white'}},
            yaxis={'title': 'Score', 'tickfont': {'color': 'white'}},
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        
        st.plotly_chart(fig, use_container_width=True)

def _display_pattern_category(patterns, pattern_keys, category_description):
    """Helper function to display pattern categories"""
    category_patterns = {k: v for k, v in patterns.items() if k in pattern_keys and v}
    
    if category_patterns:
        st.markdown(f"**{category_description}:**")
        for pattern_type, matches in category_patterns.items():
            pattern_name = pattern_type.replace('_', ' ').title()
            match_count = len(matches) if isinstance(matches, list) else 1
            
            with st.expander(f"🔍 {pattern_name} ({match_count} found)"):
                if isinstance(matches, list):
                    for i, match in enumerate(matches[:10], 1):
                        st.code(f"{i}. {match}")
                    if len(matches) > 10:
                        st.info(f"... and {len(matches) - 10} more")
                else:
                    st.code(str(matches))
    else:
        st.info(f"No {category_description.lower()} detected")

def run_comprehensive_analysis(uploaded_file, config, vt_api):
    """Run comprehensive file analysis including VirusTotal"""
    file_data = uploaded_file.getvalue()
    
    # Initialize analysis engine
    analysis_engine = AnalysisEngine()
    
    # Run the analysis
    with st.spinner("🔍 Running comprehensive file analysis..."):
        results = analysis_engine.analyze_file(file_data, uploaded_file.name, config)
    
    # Add VirusTotal scan if configured
    if vt_api.is_configured():
        with st.spinner("🌍 Scanning with VirusTotal..."):
            vt_results = vt_api.scan_file(file_data, uploaded_file.name)
            results['virustotal'] = vt_results
    else:
        results['virustotal'] = {"error": "VirusTotal API key not configured"}
    
    # Calculate threat score using ThreatScorer
    threat_scorer = ThreatScorer()
    threat_assessment = threat_scorer.calculate_score(results)
    results['threat_assessment'] = threat_assessment
    
    return results

def display_sidebar_config():
    """Display sidebar configuration options"""
    st.sidebar.markdown("## 🔧 Analysis Configuration")
    
    # VirusTotal API Key
    st.sidebar.markdown("### 🔑 VirusTotal API")
    
    current_key = st.session_state.get('vt_api_key', '')
    api_key_input = st.sidebar.text_input(
        "API Key",
        value=current_key,
        type="password",
        help="Enter your VirusTotal API key for enhanced scanning"
    )
    
    if api_key_input != current_key:
        st.session_state.vt_api_key = api_key_input
        st.sidebar.success("✅ API key updated!")
        st.rerun()
    
    if not api_key_input:
        st.sidebar.warning("⚠️ No VirusTotal API key configured")
        st.sidebar.info("💡 Get your free API key at virustotal.com")
    else:
        st.sidebar.success("🌐 VirusTotal integration enabled")
    
    # Analysis Settings
    st.sidebar.markdown("### ⚙️ Analysis Settings")
    
    config = {
        'min_string_length': st.sidebar.slider("Minimum String Length", 3, 10, 4),
        'max_strings': st.sidebar.slider("Max Strings to Extract", 50, 1000, 500),
        'deep_analysis': st.sidebar.checkbox("Deep Analysis", value=True),
        'pattern_detection': st.sidebar.checkbox("Pattern Detection", value=True),
        'entropy_analysis': st.sidebar.checkbox("Entropy Analysis", value=True),
        'signature_analysis': st.sidebar.checkbox("File Signature Analysis", value=True)
    }
    
    # Session Statistics
    if st.session_state.scan_history:
        st.sidebar.markdown("### 📊 Session Statistics")
        total_scans = len(st.session_state.scan_history)
        threat_count = sum(1 for scan in st.session_state.scan_history 
                          if scan.get('threat_detected', False))
        clean_count = total_scans - threat_count
        
        st.sidebar.metric("Total Scans", total_scans)
        st.sidebar.metric("Threats Found", threat_count)
        st.sidebar.metric("Clean Files", clean_count)
        
        if total_scans > 0:
            threat_rate = (threat_count / total_scans) * 100
            st.sidebar.metric("Detection Rate", f"{threat_rate:.1f}%")
        
        # Scan History
        with st.sidebar.expander("📜 Recent Scans"):
            for scan in st.session_state.scan_history[-5:]:  # Show last 5
                threat_icon = "🚨" if scan.get('threat_detected') else "✅"
                st.sidebar.text(f"{threat_icon} {scan.get('filename', 'Unknown')[:20]}...")
        
        # Clear history button
        if st.sidebar.button("🗑️ Clear History"):
            st.session_state.scan_history = []
            st.sidebar.success("History cleared!")
            st.rerun()
    
    return config

def main():
    """Main application function"""
    # Initialize session state
    init_session_state()
    
    # Initialize components
    vt_api = VirusTotalAPI(st.session_state.vt_api_key)
    report_generator = ReportGenerator()
    
    # Professional Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ MalwareShield Pro</h1>
        <h3>Advanced Multi-Engine Threat Detection System</h3>
        <p><em>Professional malware analysis with VirusTotal integration and comprehensive reporting</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    # System status
    display_system_status()
    
    # Sidebar configuration
    config = display_sidebar_config()
    
    # Main content area
    st.markdown("---")
    st.markdown("## 📁 File Upload & Analysis")
    
    # File uploader with enhanced styling
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        help="Upload any file for comprehensive malware analysis. Supports all file types up to 200MB.",
        type=None  # Allow all file types
    )
    
    if uploaded_file is not None:
        # Check file size (200MB limit)
        file_size = len(uploaded_file.getvalue())
        if file_size > 200 * 1024 * 1024:  # 200MB
            st.error("❌ File too large. Maximum size is 200MB.")
            return
        
        # Display file information
        display_file_info(uploaded_file)
        
        # Analysis controls
        st.markdown("### 🔬 Analysis Options")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("⚡ Quick Analysis", type="primary", use_container_width=True):
                with st.spinner("⚡ Running quick analysis..."):
                    # Basic analysis without external APIs
                    file_data = uploaded_file.getvalue()
                    
                    basic_results = {
                        'filename': uploaded_file.name,
                        'file_size': len(file_data),
                        'analysis_time': datetime.now().isoformat(),
                        'hashes': calculate_file_hashes(file_data),
                        'entropy': calculate_entropy(file_data),
                        'strings': extract_strings(file_data, config.get('min_string_length', 4), config.get('max_strings', 100)),
                        'patterns': {},
                        'threat_assessment': {'level': 'LOW', 'score': 0, 'reasons': []}
                    }
                    
                    basic_results['patterns'] = detect_patterns(file_data, basic_results['strings'])
                    
                    # Basic threat assessment
                    threat_scorer = ThreatScorer()
                    threat_assessment = threat_scorer.calculate_score(basic_results)
                    basic_results['threat_assessment'] = threat_assessment
                    
                    st.session_state.analysis_results = basic_results
                    
                    # Add to scan history
                    scan_record = {
                        'filename': uploaded_file.name,
                        'timestamp': datetime.now().isoformat(),
                        'threat_detected': threat_assessment.get('level') in ['HIGH', 'CRITICAL'],
                        'threat_level': threat_assessment.get('level', 'UNKNOWN'),
                        'analysis_type': 'quick'
                    }
                    st.session_state.scan_history.append(scan_record)
                    st.success("✅ Quick analysis completed!")
        
        with col2:
            if st.button("🌍 Full Analysis", type="secondary", use_container_width=True):
                if vt_api.is_configured():
                    with st.spinner("🔄 Running comprehensive analysis..."):
                        results = run_comprehensive_analysis(uploaded_file, config, vt_api)
                        st.session_state.analysis_results = results
                        
                        # Add to scan history
                        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
                        scan_record = {
                            'filename': uploaded_file.name,
                            'timestamp': datetime.now().isoformat(),
                            'threat_detected': threat_level in ['HIGH', 'CRITICAL'],
                            'threat_level': threat_level,
                            'analysis_type': 'full'
                        }
                        st.session_state.scan_history.append(scan_record)
                        st.success("✅ Full analysis completed!")
                else:
                    st.error("❌ VirusTotal API key required for full analysis")
                    st.info("💡 Configure your API key in the sidebar to enable full analysis")
        
        with col3:
            if st.button("📊 Generate Report", use_container_width=True):
                if st.session_state.analysis_results:
                    with st.spinner("📊 Generating comprehensive report..."):
                        report_data = report_generator.generate_report(st.session_state.analysis_results)
                        
                        # Display report summary
                        st.success("✅ Report generated successfully!")
                        
                        # Show download options
                        col_json, col_html = st.columns(2)
                        
                        with col_json:
                            json_data = report_generator.export_json(st.session_state.analysis_results)
                            st.download_button(
                                label="📄 Download JSON",
                                data=json_data,
                                file_name=f"malware_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        
                        with col_html:
                            html_data = report_generator.export_html(st.session_state.analysis_results)
                            st.download_button(
                                label="📄 Download HTML",
                                data=html_data,
                                file_name=f"malware_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                mime="text/html",
                                use_container_width=True
                            )
                else:
                    st.warning("⚠️ No analysis results to export. Run an analysis first.")
        
        with col4:
            if st.button("🗑️ Clear Results", use_container_width=True):
                st.session_state.analysis_results = None
                st.success("✅ Results cleared!")
                st.rerun()
    
    # Display analysis results
    if st.session_state.analysis_results:
        st.markdown("---")
        display_analysis_results(st.session_state.analysis_results)
    
    # Footer
    st.markdown("""
    <div class="footer">
        🛡️ <strong>MalwareShield Pro</strong> - Advanced Threat Detection System<br>
        <small>Professional malware analysis with multi-engine detection capabilities</small><br>
        <small style="color: #666;">Powered by VirusTotal API • Entropy Analysis • Pattern Detection • Behavioral Analysis</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

