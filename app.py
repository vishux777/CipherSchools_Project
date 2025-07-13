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
from datetime import datetime
from collections import Counter
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

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

try:
    from assets.lottie_animations import get_lottie_animation, display_lottie, show_result_animation
except ImportError as e:
    def get_lottie_animation(animation_type):
        return None
    def display_lottie(animation_data, key):
        st.info("🔍 Scanning in progress...")
    def show_result_animation(threat_level):
        if threat_level in ['CRITICAL', 'HIGH']:
            st.warning("⚠️ Threat detected!")
        else:
            st.success("✅ Analysis complete")

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
    background: linear-gradient(135deg, #0e1117 0%, #1a1d29 100%);
    color: #fafafa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.stApp {
    background: linear-gradient(135deg, #0e1117 0%, #1a1d29 100%);
}

/* Sidebar styling */
.css-1d391kg, .css-1544g2n {
    background: linear-gradient(180deg, #262730 0%, #1e1f26 100%);
    border-right: 2px solid #00aaff20;
}

/* Alert and notification styling */
.stAlert {
    background-color: #262730;
    border: 1px solid #444;
    color: #fafafa;
    border-radius: 10px;
}

/* File uploader styling */
.stFileUploader {
    background: linear-gradient(135deg, #262730, #1a1d29);
    border: 2px dashed #00aaff;
    border-radius: 15px;
    padding: 25px;
    text-align: center;
    transition: all 0.3s ease;
}

.stFileUploader:hover {
    border-color: #0088cc;
    box-shadow: 0 0 20px rgba(0, 170, 255, 0.2);
    transform: translateY(-2px);
}

/* Modern card styling */
.scan-card {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 25px;
    border-radius: 15px;
    border: 1px solid #444;
    margin: 15px 0;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(10px);
    transition: all 0.3s ease;
}

.scan-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 40px rgba(0, 170, 255, 0.1);
    border-color: #00aaff;
}

/* Professional header with glassmorphism */
.main-header {
    background: linear-gradient(135deg, rgba(26, 29, 41, 0.9), rgba(14, 17, 23, 0.9));
    backdrop-filter: blur(20px);
    padding: 40px 30px;
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    margin-bottom: 30px;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    position: relative;
    overflow: hidden;
}

.main-header::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(45deg, transparent 30%, rgba(0, 170, 255, 0.1) 50%, transparent 70%);
    pointer-events: none;
}

.main-header h1 {
    font-size: 3em;
    margin: 0;
    background: linear-gradient(135deg, #00aaff, #0088cc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-weight: bold;
}

.main-header h3 {
    color: #cccccc;
    font-weight: 300;
    margin: 10px 0;
}

/* Enhanced threat level banners with animations */
.threat-critical {
    background: linear-gradient(135deg, #8B0000, #DC143C);
    padding: 25px;
    border-radius: 15px;
    color: white;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 8px 32px rgba(220, 20, 60, 0.4);
    border: 2px solid #FF1744;
    animation: pulse-critical 2s infinite;
    position: relative;
    overflow: hidden;
}

.threat-critical::before {
    content: '';
    position: absolute;
    top: -2px;
    left: -2px;
    right: -2px;
    bottom: -2px;
    background: linear-gradient(45deg, #FF1744, #DC143C, #8B0000, #FF1744);
    border-radius: 15px;
    z-index: -1;
    animation: gradient-rotate 3s linear infinite;
}

@keyframes pulse-critical {
    0%, 100% { transform: scale(1); box-shadow: 0 8px 32px rgba(220, 20, 60, 0.4); }
    50% { transform: scale(1.02); box-shadow: 0 12px 40px rgba(220, 20, 60, 0.6); }
}

.threat-high {
    background: linear-gradient(135deg, #FF4500, #FF6347);
    padding: 25px;
    border-radius: 15px;
    color: white;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 8px 32px rgba(255, 99, 71, 0.4);
    border: 2px solid #FF5722;
    animation: pulse-high 2.5s infinite;
}

@keyframes pulse-high {
    0%, 100% { box-shadow: 0 8px 32px rgba(255, 99, 71, 0.4); }
    50% { box-shadow: 0 12px 40px rgba(255, 99, 71, 0.6); }
}

.threat-medium {
    background: linear-gradient(135deg, #FF8C00, #FFA500);
    padding: 25px;
    border-radius: 15px;
    color: white;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 8px 32px rgba(255, 165, 0, 0.4);
    border: 2px solid #FF9800;
}

.threat-low {
    background: linear-gradient(135deg, #228B22, #32CD32);
    padding: 25px;
    border-radius: 15px;
    color: white;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 8px 32px rgba(50, 205, 50, 0.4);
    border: 2px solid #4CAF50;
}

.threat-clean {
    background: linear-gradient(135deg, #228B22, #32CD32);
    padding: 25px;
    border-radius: 15px;
    color: white;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 8px 32px rgba(50, 205, 50, 0.4);
    border: 2px solid #4CAF50;
    animation: pulse-clean 3s infinite;
}

@keyframes pulse-clean {
    0%, 100% { box-shadow: 0 8px 32px rgba(50, 205, 50, 0.4); }
    50% { box-shadow: 0 12px 40px rgba(50, 205, 50, 0.6); }
}

@keyframes gradient-rotate {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
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

/* Enhanced button styling */
.stButton > button {
    background: linear-gradient(135deg, #00aaff, #0088cc);
    border: none;
    color: white;
    border-radius: 12px;
    padding: 12px 24px;
    font-weight: 600;
    font-size: 16px;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 4px 15px rgba(0, 170, 255, 0.3);
    position: relative;
    overflow: hidden;
}

.stButton > button::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
    transition: left 0.5s ease;
}

.stButton > button:hover::before {
    left: 100%;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #0088cc, #006699);
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 170, 255, 0.4);
}

.stButton > button:active {
    transform: translateY(0);
    box-shadow: 0 4px 15px rgba(0, 170, 255, 0.3);
}

/* Radio button styling */
.stRadio > div {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 15px;
    border-radius: 12px;
    border: 1px solid #444;
}

/* Text input styling */
.stTextInput > div > div > input {
    background: linear-gradient(135deg, #262730, #1a1d29);
    color: #fafafa;
    border: 2px solid #444;
    border-radius: 10px;
    padding: 12px 16px;
    transition: all 0.3s ease;
}

.stTextInput > div > div > input:focus {
    border-color: #00aaff;
    box-shadow: 0 0 15px rgba(0, 170, 255, 0.3);
    outline: none;
}

/* Metric styling */
.metric-container {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 20px;
    border-radius: 15px;
    border: 1px solid #444;
    margin: 10px 0;
    text-align: center;
    transition: all 0.3s ease;
}

.metric-container:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 30px rgba(0, 170, 255, 0.1);
    border-color: #00aaff;
}

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    background: linear-gradient(135deg, #262730, #1a1d29);
    border-radius: 12px;
    padding: 5px;
}

.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 8px;
    color: #cccccc;
    transition: all 0.3s ease;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, #00aaff, #0088cc);
    color: white;
}

/* Progress bar styling */
.stProgress > div > div {
    background: linear-gradient(90deg, #00aaff, #0088cc);
    border-radius: 10px;
}

.stProgress > div {
    background-color: #333;
    border-radius: 10px;
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
        'file_paths': re.compile(r'[A-Za-z]:\\[^\\]+(?:\\[^\\]+)*', re.IGNORECASE),
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

def display_threat_banner(threat_level, threat_score, reasons):
    """Display threat level banner"""
    threat_classes = {
        'CLEAN': 'threat-clean',
        'LOW': 'threat-low',
        'MEDIUM': 'threat-medium',
        'HIGH': 'threat-high',
        'CRITICAL': 'threat-critical'
    }
    
    icons = {
        'CLEAN': '✅',
        'LOW': '⚠️',
        'MEDIUM': '🚨',
        'HIGH': '🔴',
        'CRITICAL': '☠️'
    }
    
    class_name = threat_classes.get(threat_level, 'threat-clean')
    icon = icons.get(threat_level, '❓')
    
    banner_html = f"""
    <div class="{class_name}">
        <h2>{icon} THREAT LEVEL: {threat_level}</h2>
        <h3>Security Score: {threat_score}/100</h3>
        <p>Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """
    
    st.markdown(banner_html, unsafe_allow_html=True)
    
    if reasons:
        with st.expander(f"📋 Analysis Details ({len(reasons)} findings)"):
            for i, reason in enumerate(reasons, 1):
                st.write(f"{i}. {reason}")

def display_file_metadata(file_data, filename, hashes):
    """Display file metadata in a professional format"""
    st.subheader("📁 File Information")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h4>🏷️ File Details</h4>
        </div>
        """, unsafe_allow_html=True)
        
        st.metric("Filename", filename)
        st.metric("Size", format_file_size(len(file_data)))
        st.metric("Type", filename.split('.')[-1].upper() if '.' in filename else "Unknown")
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h4>🔐 Hash Values</h4>
        </div>
        """, unsafe_allow_html=True)
        
        st.text_area("MD5", hashes['md5'], height=68)
        st.text_area("SHA1", hashes['sha1'], height=68)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h4>🔍 Advanced Hash</h4>
        </div>
        """, unsafe_allow_html=True)
        
        st.text_area("SHA256", hashes['sha256'], height=120)

def display_analysis_results(results):
    """Display comprehensive analysis results"""
    if not results:
        st.error("No analysis results available")
        return
    
    # Display threat banner
    threat_info = results.get('threat_assessment', {})
    display_threat_banner(
        threat_info.get('level', 'UNKNOWN'),
        threat_info.get('score', 0),
        threat_info.get('reasons', [])
    )
    
    # File metadata
    if 'file_info' in results:
        file_info = results['file_info']
        display_file_metadata(
            results.get('file_data', b''),
            file_info.get('filename', 'unknown'),
            file_info.get('hashes', {})
        )
    
    # Analysis tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔬 Technical Analysis", "🌐 VirusTotal Results", "📊 Visualizations", "📋 Patterns & IOCs"])
    
    with tab1:
        display_technical_analysis(results)
    
    with tab2:
        display_virustotal_results(results)
    
    with tab3:
        display_visualizations(results)
    
    with tab4:
        display_patterns_and_iocs(results)

def display_technical_analysis(results):
    """Display technical analysis details"""
    st.subheader("🔬 Technical Analysis")
    
    analysis = results.get('analysis', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📈 Entropy Analysis")
        entropy = analysis.get('entropy', 0)
        st.metric("File Entropy", f"{entropy:.2f}")
        
        if entropy > 7.5:
            st.warning("⚠️ High entropy detected - possible encryption/packing")
        elif entropy < 1.0:
            st.info("ℹ️ Low entropy - likely text or structured data")
        else:
            st.success("✅ Normal entropy range")
    
    with col2:
        st.markdown("#### 🧬 Binary Analysis")
        if 'strings' in analysis:
            strings_count = len(analysis['strings'])
            st.metric("Extracted Strings", strings_count)
        
        if 'file_type' in analysis:
            st.metric("Detected Type", analysis['file_type'])

def display_virustotal_results(results):
    """Display VirusTotal scan results"""
    st.subheader("🌐 VirusTotal Analysis")
    
    vt_results = results.get('virustotal', {})
    
    if 'error' in vt_results:
        st.error(f"VirusTotal Error: {vt_results['error']}")
        return
    
    if not vt_results:
        st.info("No VirusTotal results available")
        return
    
    # Detection summary
    stats = vt_results.get('stats', {})
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🛡️ Clean", stats.get('harmless', 0))
        with col2:
            st.metric("⚠️ Suspicious", stats.get('suspicious', 0))
        with col3:
            st.metric("🔴 Malicious", stats.get('malicious', 0))
        with col4:
            st.metric("❓ Undetected", stats.get('undetected', 0))
    
    # Detailed results
    scans = vt_results.get('scans', {})
    if scans:
        st.markdown("#### 🔍 Engine Detection Results")
        
        detection_data = []
        for engine, result in scans.items():
            detection_data.append({
                'Engine': engine,
                'Status': result.get('result', 'Clean'),
                'Version': result.get('version', 'N/A'),
                'Update': result.get('update', 'N/A')
            })
        
        df = pd.DataFrame(detection_data)
        st.dataframe(df, use_container_width=True)

def display_visualizations(results):
    """Display analysis visualizations"""
    st.subheader("📊 Analysis Visualizations")
    
    # Threat score gauge
    threat_info = results.get('threat_assessment', {})
    score = threat_info.get('score', 0)
    
    fig_gauge = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Threat Score"},
        delta = {'reference': 50},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 25], 'color': "lightgreen"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 75
            }
        }
    ))
    
    fig_gauge.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={'color': "white"}
    )
    
    st.plotly_chart(fig_gauge, use_container_width=True)
    
    # Entropy visualization
    analysis = results.get('analysis', {})
    if 'entropy' in analysis:
        entropy = analysis['entropy']
        
        fig_bar = go.Figure(data=[
            go.Bar(x=['File Entropy'], y=[entropy], marker_color='cyan')
        ])
        
        fig_bar.update_layout(
            title="File Entropy Analysis",
            yaxis_title="Entropy Value",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={'color': "white"}
        )
        
        st.plotly_chart(fig_bar, use_container_width=True)

def display_patterns_and_iocs(results):
    """Display detected patterns and IOCs"""
    st.subheader("📋 Indicators of Compromise (IOCs)")
    
    patterns = results.get('patterns', {})
    
    if not patterns:
        st.info("No suspicious patterns detected")
        return
    
    for pattern_type, matches in patterns.items():
        if matches:
            with st.expander(f"🔍 {pattern_type.replace('_', ' ').title()} ({len(matches)} found)"):
                for match in matches:
                    st.code(match)

def perform_local_scan(file_data, filename):
    """Perform local file analysis"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Display scanning animation
    animation_placeholder = st.empty()
    with animation_placeholder:
        display_lottie(get_lottie_animation("scanning"), "local_scan")
    
    try:
        status_text.text("Initializing analysis...")
        progress_bar.progress(10)
        
        # Initialize analysis engine
        engine = AnalysisEngine()
        scorer = ThreatScorer()
        
        status_text.text("Calculating file hashes...")
        progress_bar.progress(20)
        hashes = calculate_file_hashes(file_data)
        
        status_text.text("Analyzing file entropy...")
        progress_bar.progress(40)
        entropy = calculate_entropy(file_data)
        
        status_text.text("Extracting strings...")
        progress_bar.progress(60)
        strings = extract_strings(file_data)
        
        status_text.text("Detecting patterns...")
        progress_bar.progress(80)
        patterns = detect_patterns(file_data, strings)
        
        status_text.text("Calculating threat score...")
        progress_bar.progress(90)
        
        # Prepare analysis data
        analysis_data = {
            'entropy': entropy,
            'strings': strings,
            'patterns': patterns,
            'file_size': len(file_data),
            'hashes': hashes
        }
        
        threat_assessment = scorer.calculate_score(analysis_data)
        
        # Compile results
        results = {
            'file_info': {
                'filename': filename,
                'size': len(file_data),
                'hashes': hashes
            },
            'analysis': {
                'entropy': entropy,
                'strings': strings,
                'file_type': filename.split('.')[-1] if '.' in filename else 'unknown'
            },
            'patterns': patterns,
            'threat_assessment': threat_assessment,
            'scan_type': 'local',
            'timestamp': datetime.now().isoformat()
        }
        
        progress_bar.progress(100)
        status_text.text("Analysis complete!")
        time.sleep(1)
        
        # Clear animation and progress
        animation_placeholder.empty()
        progress_bar.empty()
        status_text.empty()
        
        return results
        
    except Exception as e:
        animation_placeholder.empty()
        progress_bar.empty()
        status_text.empty()
        st.error(f"Analysis failed: {str(e)}")
        return None

def perform_virustotal_scan(file_data, filename, api_key):
    """Perform VirusTotal scan"""
    if not api_key:
        st.error("VirusTotal API key is required")
        return None
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Display scanning animation
    animation_placeholder = st.empty()
    with animation_placeholder:
        display_lottie(get_lottie_animation("virustotal"), "vt_scan")
    
    try:
        vt_api = VirusTotalAPI(api_key)
        
        if not vt_api.is_configured():
            st.error("Invalid VirusTotal API key")
            return None
        
        status_text.text("Submitting file to VirusTotal...")
        progress_bar.progress(20)
        
        # Calculate hashes for local analysis
        hashes = calculate_file_hashes(file_data)
        
        status_text.text("Scanning with VirusTotal...")
        progress_bar.progress(50)
        
        # Perform VirusTotal scan
        vt_results = vt_api.scan_file(file_data, filename)
        
        status_text.text("Processing results...")
        progress_bar.progress(80)
        
        # Perform local analysis as well
        entropy = calculate_entropy(file_data)
        strings = extract_strings(file_data)
        patterns = detect_patterns(file_data, strings)
        
        # Calculate threat score
        scorer = ThreatScorer()
        analysis_data = {
            'entropy': entropy,
            'strings': strings,
            'patterns': patterns,
            'file_size': len(file_data),
            'hashes': hashes,
            'virustotal': vt_results
        }
        
        threat_assessment = scorer.calculate_score(analysis_data)
        
        # Compile results
        results = {
            'file_info': {
                'filename': filename,
                'size': len(file_data),
                'hashes': hashes
            },
            'analysis': {
                'entropy': entropy,
                'strings': strings,
                'file_type': filename.split('.')[-1] if '.' in filename else 'unknown'
            },
            'patterns': patterns,
            'virustotal': vt_results,
            'threat_assessment': threat_assessment,
            'scan_type': 'virustotal',
            'timestamp': datetime.now().isoformat()
        }
        
        progress_bar.progress(100)
        status_text.text("Scan complete!")
        time.sleep(1)
        
        # Clear animation and progress
        animation_placeholder.empty()
        progress_bar.empty()
        status_text.empty()
        
        return results
        
    except Exception as e:
        animation_placeholder.empty()
        progress_bar.empty()
        status_text.empty()
        st.error(f"VirusTotal scan failed: {str(e)}")
        return None

def generate_pdf_report(results):
    """Generate and provide PDF report download"""
    if not results:
        st.error("No results available for report generation")
        return
    
    try:
        report_gen = ReportGenerator()
        pdf_data = report_gen.generate_report(results)
        
        if isinstance(pdf_data, dict) and 'error' in pdf_data:
            st.error(f"Report generation failed: {pdf_data['error']}")
            return
        
        # Create download button
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"malware_scan_report_{timestamp}.pdf"
        
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_data,
            file_name=filename,
            mime="application/pdf",
            use_container_width=True
        )
        
    except Exception as e:
        st.error(f"Failed to generate PDF report: {str(e)}")

def main():
    """Main application function"""
    # Initialize session state
    init_session_state()
    
    # Main header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ MalwareShield Pro</h1>
        <h3>Advanced Threat Detection & Analysis Platform</h3>
        <p>Professional malware scanning with VirusTotal integration</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### 🔧 Scan Options")
        
        scan_mode = st.radio(
            "Select Scan Mode:",
            ["🔍 Local File Scan", "🌐 VirusTotal Scan"],
            index=0
        )
        
        st.markdown("---")
        
        # VirusTotal API key input
        if scan_mode == "🌐 VirusTotal Scan":
            st.markdown("### 🔑 VirusTotal Configuration")
            api_key = st.text_input(
                "API Key:",
                value=st.session_state.vt_api_key,
                type="password",
                help="Enter your VirusTotal API key"
            )
            st.session_state.vt_api_key = api_key
            
            if api_key:
                st.success("✅ API Key configured")
            else:
                st.warning("⚠️ API Key required for VirusTotal scans")
        
        st.markdown("---")
        
        # Scan history
        if st.session_state.scan_history:
            st.markdown("### 📊 Recent Scans")
            for i, scan in enumerate(reversed(st.session_state.scan_history[-5:])):
                timestamp = scan.get('timestamp', 'Unknown')
                threat_level = scan.get('threat_assessment', {}).get('level', 'Unknown')
                st.text(f"{timestamp[:16]} - {threat_level}")
    
    # Main content area
    if scan_mode == "🔍 Local File Scan":
        st.markdown("""
        <div class="scan-card">
            <h2>🔍 Local File Analysis</h2>
            <p style="font-size: 1.1em; color: #cccccc; margin-bottom: 20px;">
                Advanced offline malware detection using entropy analysis, pattern recognition, and threat intelligence
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 25px;">
                <div style="background: rgba(0, 170, 255, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #00aaff;">
                    <strong>🧬 Entropy Analysis</strong><br>
                    <small>Detect encryption and packing</small>
                </div>
                <div style="background: rgba(0, 170, 255, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #00aaff;">
                    <strong>🔍 Pattern Detection</strong><br>
                    <small>Identify malicious indicators</small>
                </div>
                <div style="background: rgba(0, 170, 255, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #00aaff;">
                    <strong>📊 Threat Scoring</strong><br>
                    <small>AI-powered risk assessment</small>
                </div>
                <div style="background: rgba(0, 170, 255, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #00aaff;">
                    <strong>⚡ Offline Analysis</strong><br>
                    <small>No external dependencies</small>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Choose a file to analyze",
            type=None,
            help="Upload any file for malware analysis"
        )
        
        if uploaded_file is not None:
            file_data = uploaded_file.read()
            filename = uploaded_file.name
            
            # File info
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📁 Filename", filename)
            with col2:
                st.metric("📏 Size", format_file_size(len(file_data)))
            with col3:
                st.metric("🏷️ Type", filename.split('.')[-1].upper() if '.' in filename else "Unknown")
            
            if st.button("🚀 Start Local Analysis", use_container_width=True):
                # Show scanning animation
                with st.spinner(""):
                    animation_data = get_lottie_animation("scanning")
                    display_lottie(animation_data, "local_scan_animation")
                    
                    # Perform scan
                    results = perform_local_scan(file_data, filename)
                    if results:
                        st.session_state.analysis_results = results
                        st.session_state.scan_history.append(results)
                        
                        # Show success animation
                        threat_level = results.get('threat_assessment', {}).get('level', 'UNKNOWN')
                        show_result_animation(threat_level)
                        
                        time.sleep(1)  # Brief pause to show result
                        st.rerun()
    
    elif scan_mode == "🌐 VirusTotal Scan":
        st.markdown("""
        <div class="scan-card">
            <h2>🌐 VirusTotal Integration</h2>
            <p style="font-size: 1.1em; color: #cccccc; margin-bottom: 20px;">
                Cloud-powered threat detection using 70+ antivirus engines and global threat intelligence
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 25px;">
                <div style="background: rgba(30, 136, 229, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #1e88e5;">
                    <strong>🔍 Multi-Engine Detection</strong><br>
                    <small>70+ antivirus engines</small>
                </div>
                <div style="background: rgba(30, 136, 229, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #1e88e5;">
                    <strong>🌐 Global Intelligence</strong><br>
                    <small>Real-time threat database</small>
                </div>
                <div style="background: rgba(30, 136, 229, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #1e88e5;">
                    <strong>📊 Reputation Analysis</strong><br>
                    <small>Comprehensive file scoring</small>
                </div>
                <div style="background: rgba(30, 136, 229, 0.1); padding: 15px; border-radius: 10px; border-left: 4px solid #1e88e5;">
                    <strong>🔄 Live Updates</strong><br>
                    <small>Always current detection</small>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Check API key
        if not st.session_state.vt_api_key:
            st.warning("⚠️ Please configure your VirusTotal API key in the sidebar")
            st.info("You can get a free API key from: https://www.virustotal.com/gui/join-us")
        else:
            # File upload or hash input
            scan_option = st.radio(
                "Scan Method:",
                ["📁 Upload File", "🔢 Enter File Hash"],
                horizontal=True
            )
            
            if scan_option == "📁 Upload File":
                uploaded_file = st.file_uploader(
                    "Choose a file to scan with VirusTotal",
                    type=None,
                    help="Upload file for VirusTotal analysis"
                )
                
                if uploaded_file is not None:
                    file_data = uploaded_file.read()
                    filename = uploaded_file.name
                    
                    # File info
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("📁 Filename", filename)
                    with col2:
                        st.metric("📏 Size", format_file_size(len(file_data)))
                    with col3:
                        st.metric("🏷️ Type", filename.split('.')[-1].upper() if '.' in filename else "Unknown")
                    
                    if st.button("🚀 Scan with VirusTotal", use_container_width=True):
                        results = perform_virustotal_scan(file_data, filename, st.session_state.vt_api_key)
                        if results:
                            st.session_state.analysis_results = results
                            st.session_state.scan_history.append(results)
                            st.rerun()
            
            elif scan_option == "🔢 Enter File Hash":
                hash_input = st.text_input(
                    "File Hash (MD5, SHA1, or SHA256):",
                    placeholder="Enter file hash for analysis",
                    help="Paste a file hash to check VirusTotal database"
                )
                
                if hash_input and st.button("🔍 Query Hash", use_container_width=True):
                    # Implement hash lookup
                    st.info("Hash lookup feature - coming soon!")
    
    # Display results if available
    if st.session_state.analysis_results:
        st.markdown("---")
        st.markdown("## 📋 Analysis Results")
        
        results = st.session_state.analysis_results
        display_analysis_results(results)
        
        # Report generation section
        st.markdown("---")
        st.markdown("### 📄 Report Generation")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📄 Generate PDF Report", use_container_width=True):
                generate_pdf_report(results)
        
        with col2:
            # JSON export
            if st.button("📋 Export JSON", use_container_width=True):
                report_gen = ReportGenerator()
                json_data = report_gen.export_json(results)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"scan_results_{timestamp}.json"
                
                st.download_button(
                    label="💾 Download JSON",
                    data=json_data,
                    file_name=filename,
                    mime="application/json"
                )
        
        with col3:
            if st.button("🔄 New Scan", use_container_width=True):
                st.session_state.analysis_results = None
                st.rerun()
    
    # Footer
    st.markdown("""
    <div class="footer">
        <p>🛡️ MalwareShield Pro - Professional Threat Detection Platform</p>
        <p>Created with 💗 by vishux777 | Enhanced with VirusTotal API</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
