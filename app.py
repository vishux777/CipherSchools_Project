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

# Import utility modules with fallback handling
try:
    from utils.virustotal import VirusTotalAPI
except ImportError:
    st.warning("VirusTotal module not available - using fallback")
    class VirusTotalAPI:
        def __init__(self, api_key):
            self.api_key = api_key
        def scan_file(self, file_data, filename):
            return {"error": "VirusTotal API not available"}
        def get_file_report(self, file_hash):
            return {"error": "VirusTotal API not available"}

try:
    from utils.report_generator import ReportGenerator
except ImportError:
    st.warning("Report Generator module not available - using fallback")
    class ReportGenerator:
        def generate_report(self, results):
            return {"error": "Report generator not available"}
        def export_json(self, results):
            return json.dumps(results, indent=2)

try:
    from utils.analysis_engine import AnalysisEngine
except ImportError:
    st.warning("Analysis Engine module not available - using fallback")
    class AnalysisEngine:
        def analyze_file(self, file_data, filename, config):
            return {"error": "Analysis engine not available"}

# Configure page
st.set_page_config(
    page_title="MalwareShield Pro - Advanced Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
def init_session_state():
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
    size_names = ["B", "KB", "MB", "GB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def get_threat_color(threat_level):
    """Get color based on threat level"""
    colors = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107', 
        'HIGH': '#dc3545',
        'CRITICAL': '#6f42c1'
    }
    return colors.get(threat_level.upper(), '#6c757d')

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
        'crypto_indicators': re.compile(r'\b(bitcoin|btc|wallet|private[_\s]?key|encryption|decrypt|cipher)\b', re.IGNORECASE)
    }
    
    detected = {}
    file_string = ' '.join(strings_list)
    
    for pattern_name, pattern in patterns.items():
        matches = pattern.findall(file_string)
        if matches:
            detected[pattern_name] = list(set(matches))  # Remove duplicates
    
    return detected

def run_basic_analysis(uploaded_file, config):
    """Run basic file analysis without external dependencies"""
    file_data = uploaded_file.getvalue()
    
    # Basic analysis components
    results = {
        'filename': uploaded_file.name,
        'file_size': len(file_data),
        'analysis_time': datetime.now().isoformat(),
        'hashes': calculate_file_hashes(file_data),
        'entropy': calculate_entropy(file_data),
        'strings': extract_strings(file_data, config.get('min_string_length', 4), config.get('max_strings', 100)),
        'patterns': {},
        'threat_assessment': {'level': 'LOW', 'score': 0, 'reasons': []}
    }
    
    # Extract patterns
    results['patterns'] = detect_patterns(file_data, results['strings'])
    
    # Basic threat assessment
    threat_score = 0
    reasons = []
    
    # Check entropy (high entropy might indicate encryption/packing)
    entropy_value = results['entropy']
    if isinstance(entropy_value, dict):
        entropy_value = entropy_value.get('overall_entropy', 0)
    
    if entropy_value > 7.5:
        threat_score += 30
        reasons.append("High entropy detected - possible encryption/packing")
    
    # Check for suspicious patterns
    if results['patterns'].get('suspicious_apis'):
        threat_score += 40
        reasons.append("Suspicious API calls detected")
    
    if results['patterns'].get('crypto_indicators'):
        threat_score += 20
        reasons.append("Cryptocurrency-related strings found")
    
    if results['patterns'].get('urls'):
        threat_score += 10
        reasons.append("URLs found in file")
    
    # Determine threat level
    if threat_score >= 70:
        level = 'CRITICAL'
    elif threat_score >= 50:
        level = 'HIGH'
    elif threat_score >= 30:
        level = 'MEDIUM'
    else:
        level = 'LOW'
    
    results['threat_assessment'] = {
        'level': level,
        'score': threat_score,
        'reasons': reasons
    }
    
    return results

def display_system_status():
    """Display real-time system status indicators"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "🔧 Analysis Engine",
            "Online",
            delta="✅ Ready"
        )
    
    with col2:
        vt_status = "Connected" if st.session_state.vt_api_key else "Offline"
        vt_delta = "🌐 API Active" if st.session_state.vt_api_key else "❌ No API Key"
        st.metric(
            "🌍 VirusTotal",
            vt_status,
            delta=vt_delta
        )
    
    with col3:
        st.metric(
            "📊 Scans Today",
            len(st.session_state.scan_history),
            delta="Active Session"
        )
    
    with col4:
        threat_count = sum(1 for scan in st.session_state.scan_history 
                          if scan.get('threat_detected', False))
        st.metric(
            "⚠️ Threats Detected",
            threat_count,
            delta="This Session"
        )

def display_sidebar_stats():
    """Display quick statistics in sidebar"""
    if st.session_state.scan_history:
        total_scans = len(st.session_state.scan_history)
        threat_count = sum(1 for scan in st.session_state.scan_history 
                          if scan.get('threat_detected', False))
        clean_count = total_scans - threat_count
        
        st.markdown("### 📊 Session Statistics")
        st.metric("Total Scans", total_scans)
        st.metric("Threats Found", threat_count)
        st.metric("Clean Files", clean_count)
        
        if total_scans > 0:
            threat_rate = (threat_count / total_scans) * 100
            st.metric("Detection Rate", f"{threat_rate:.1f}%")
    else:
        st.info("No scans performed yet")

def display_file_info(uploaded_file):
    """Display enhanced file information"""
    file_size = len(uploaded_file.getvalue())
    file_type = uploaded_file.type or 'Unknown'
    
    st.subheader("📄 File Information")
    
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**📝 Name:** {uploaded_file.name}")
        st.write(f"**📏 Size:** {format_file_size(file_size)}")
    
    with col2:
        st.write(f"**🏷️ Type:** {file_type}")
        st.write(f"**⏰ Uploaded:** {datetime.now().strftime('%H:%M:%S')}")

def display_analysis_results(results):
    """Display comprehensive analysis results"""
    st.header("📊 Analysis Results")
    
    # Threat Assessment
    threat_level = results.get('threat_assessment', {}).get('level', 'Unknown')
    threat_score = results.get('threat_assessment', {}).get('score', 0)
    threat_reasons = results.get('threat_assessment', {}).get('reasons', [])
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        threat_color = get_threat_color(threat_level)
        st.markdown(f"### Threat Level: <span style='color: {threat_color}'>{threat_level}</span>", unsafe_allow_html=True)
    
    with col2:
        st.metric("Threat Score", f"{threat_score}/100")
    
    with col3:
        st.metric("File Size", format_file_size(results.get('file_size', 0)))
    
    # Threat Reasons
    if threat_reasons:
        st.subheader("⚠️ Threat Indicators")
        for reason in threat_reasons:
            st.warning(f"• {reason}")
    
    # File Hashes
    if 'hashes' in results:
        st.subheader("🔍 File Hashes")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.text_input("MD5", results['hashes']['md5'], disabled=True)
        with col2:
            st.text_input("SHA1", results['hashes']['sha1'], disabled=True)
        with col3:
            st.text_input("SHA256", results['hashes']['sha256'], disabled=True)
    
    # Entropy Analysis
    if 'entropy' in results:
        st.subheader("📈 Entropy Analysis")
        entropy_value = results['entropy']
        if isinstance(entropy_value, dict):
            entropy_value = entropy_value.get('overall_entropy', 0)
        
        # Create entropy gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=entropy_value,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "File Entropy"},
            gauge={
                'axis': {'range': [None, 8]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 4], 'color': "lightgray"},
                    {'range': [4, 6], 'color': "yellow"},
                    {'range': [6, 8], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 7.5
                }
            }
        ))
        
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
        
        if entropy_value > 7.5:
            st.warning("⚠️ High entropy detected - file may be encrypted or packed")
        elif entropy_value > 6:
            st.info("ℹ️ Moderate entropy - file contains mixed content")
        else:
            st.success("✅ Low entropy - file appears to be normal text/code")
    
    # Patterns Detection
    if 'patterns' in results and results['patterns']:
        st.subheader("🎯 Pattern Detection")
        
        for pattern_type, matches in results['patterns'].items():
            if matches:
                st.write(f"**{pattern_type.replace('_', ' ').title()}:**")
                for match in matches[:10]:  # Show first 10 matches
                    st.code(match)
                if len(matches) > 10:
                    st.write(f"... and {len(matches) - 10} more")
    
    # Strings Analysis
    if 'strings' in results and results['strings']:
        st.subheader("📝 String Analysis")
        
        strings_data = results['strings']
        if isinstance(strings_data, dict):
            # Handle new structured format
            all_strings = []
            if 'ascii_strings' in strings_data:
                all_strings.extend(strings_data['ascii_strings'])
            if 'unicode_strings' in strings_data:
                all_strings.extend(strings_data['unicode_strings'])
            
            if all_strings:
                with st.expander(f"Extracted Strings ({len(all_strings)} found)"):
                    strings_text = '\n'.join(all_strings[:50])  # Show first 50
                    st.text_area("Strings", strings_text, height=300, disabled=True)
                    
                    if len(all_strings) > 50:
                        st.info(f"Showing first 50 strings. Total: {len(all_strings)}")
        elif isinstance(strings_data, list):
            # Handle old format
            with st.expander(f"Extracted Strings ({len(strings_data)} found)"):
                strings_text = '\n'.join(strings_data[:50])  # Show first 50
                st.text_area("Strings", strings_text, height=300, disabled=True)
                
                if len(strings_data) > 50:
                    st.info(f"Showing first 50 strings. Total: {len(strings_data)}")
    
    # Export Results
    st.subheader("📥 Export Results")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Download JSON Report"):
            json_data = json.dumps(results, indent=2, default=str)
            st.download_button(
                label="Download Report",
                data=json_data,
                file_name=f"malware_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📋 Copy Results"):
            st.code(json.dumps(results, indent=2, default=str))

def main():
    # Initialize session state
    init_session_state()
    
    # Initialize components
    vt_api = VirusTotalAPI(st.session_state.vt_api_key)
    analysis_engine = AnalysisEngine()
    report_generator = ReportGenerator()
    
    # Header
    st.title("🛡️ MalwareShield Pro")
    st.markdown("### Advanced Multi-Engine Threat Detection System")
    st.markdown("*Now with VirusTotal Integration*")
    
    # Real-time status indicators
    display_system_status()
    
    # Sidebar configuration
    with st.sidebar:
        st.header("🔧 Analysis Configuration")
        
        # VirusTotal API Key configuration
        st.subheader("🔑 VirusTotal API")
        api_key_input = st.text_input(
            "API Key",
            value=st.session_state.vt_api_key,
            type="password",
            help="Enter your VirusTotal API key for enhanced scanning"
        )
        
        if api_key_input != st.session_state.vt_api_key:
            st.session_state.vt_api_key = api_key_input
            vt_api = VirusTotalAPI(api_key_input)
            st.rerun()
        
        # Analysis modules
        st.subheader("🎯 Analysis Modules")
        hash_analysis = st.checkbox("🔍 Hash Analysis", value=True)
        entropy_analysis = st.checkbox("📊 Entropy Analysis", value=True)
        string_extraction = st.checkbox("📝 String Extraction", value=True)
        pattern_detection = st.checkbox("🎯 Pattern Detection", value=True)
        vt_scan = st.checkbox("🌐 VirusTotal Scan", value=bool(st.session_state.vt_api_key))
        
        st.markdown("---")
        
        # Advanced settings
        st.subheader("⚙️ Advanced Settings")
        max_strings = st.slider("Max Strings to Extract", 50, 1000, 200)
        min_string_length = st.slider("Min String Length", 3, 20, 4)
        sensitivity_level = st.selectbox("Detection Sensitivity", ["Low", "Medium", "High"], index=1)
        
        st.markdown("---")
        
        # Quick stats
        display_sidebar_stats()
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # File upload section
        st.header("📁 File Upload & Analysis")
        
        uploaded_file = st.file_uploader(
            "Drag and drop your file here or click to browse",
            type=None,
            help="Upload any file for comprehensive malware analysis. Maximum file size: 200MB"
        )
        
        if uploaded_file is not None:
            st.session_state.uploaded_file = uploaded_file
            display_file_info(uploaded_file)
            
            # Analysis button
            if st.button("🔍 Start Comprehensive Analysis", type="primary", use_container_width=True):
                with st.spinner("🔍 Analyzing file... Please wait"):
                    # Create analysis configuration
                    config = {
                        'hash_analysis': hash_analysis,
                        'string_extraction': string_extraction,
                        'entropy_analysis': entropy_analysis,
                        'pattern_detection': pattern_detection,
                        'vt_scan': vt_scan,
                        'max_strings': max_strings,
                        'min_string_length': min_string_length,
                        'sensitivity_level': sensitivity_level
                    }
                    
                    # Run analysis
                    try:
                        results = analysis_engine.analyze_file(uploaded_file.getvalue(), uploaded_file.name, config)
                        if 'error' in results:
                            st.error(f"Analysis failed: {results['error']}")
                            # Fallback to basic analysis
                            results = run_basic_analysis(uploaded_file, config)
                    except Exception as e:
                        st.error(f"Analysis error: {str(e)}")
                        # Fallback to basic analysis
                        results = run_basic_analysis(uploaded_file, config)
                    
                    # Store results
                    st.session_state.analysis_results = results
                    
                    # Add to scan history
                    scan_record = {
                        'filename': uploaded_file.name,
                        'timestamp': datetime.now().isoformat(),
                        'threat_detected': results.get('threat_assessment', {}).get('level', 'LOW') != 'LOW',
                        'threat_level': results.get('threat_assessment', {}).get('level', 'LOW')
                    }
                    st.session_state.scan_history.append(scan_record)
                    
                    st.success("✅ Analysis completed!")
                    st.rerun()
    
    with col2:
        # Statistics panel
        st.header("📈 Real-time Statistics")
        
        if st.session_state.analysis_results:
            results = st.session_state.analysis_results
            
            # Threat level display
            threat_level = results.get('threat_assessment', {}).get('level', 'Unknown')
            threat_color = get_threat_color(threat_level)
            
            st.markdown(f"### Current Threat Level")
            st.markdown(f"<h2 style='color: {threat_color}; text-align: center;'>{threat_level}</h2>", unsafe_allow_html=True)
            
            # Analysis progress
            completed_modules = sum([
                bool(results.get('hashes')),
                bool(results.get('strings')),
                bool(results.get('entropy')),
                bool(results.get('patterns')),
                bool(results.get('virustotal')),
                bool(results.get('behavioral'))
            ])
            
            st.metric("Analysis Progress", f"{completed_modules}/6 modules")
            
            # Quick stats
            if 'entropy' in results:
                entropy_value = results['entropy']
                if isinstance(entropy_value, dict):
                    entropy_value = entropy_value.get('overall_entropy', 0)
                st.metric("File Entropy", f"{entropy_value:.2f}")
            
            if 'strings' in results:
                strings_data = results['strings']
                if isinstance(strings_data, dict):
                    strings_count = strings_data.get('total_strings', 0)
                    if strings_count == 0:
                        strings_count = len(strings_data.get('ascii_strings', []))
                elif isinstance(strings_data, list):
                    strings_count = len(strings_data)
                else:
                    strings_count = 0
                st.metric("Strings Found", strings_count)
            
            if 'patterns' in results:
                patterns_data = results['patterns']
                if isinstance(patterns_data, dict):
                    pattern_count = 0
                    for key, matches in patterns_data.items():
                        if isinstance(matches, list):
                            pattern_count += len(matches)
                        elif isinstance(matches, dict):
                            pattern_count += len(matches.get('matches', []))
                else:
                    pattern_count = 0
                st.metric("Patterns Detected", pattern_count)
        else:
            st.info("📊 Upload a file to see analysis statistics")
    
    # Results display
    if st.session_state.analysis_results:
        st.markdown("---")
        display_analysis_results(st.session_state.analysis_results)
    
    # Scan History
    if st.session_state.scan_history:
        st.markdown("---")
        st.header("📋 Scan History")
        
        # Convert to DataFrame for better display
        df = pd.DataFrame(st.session_state.scan_history)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp', ascending=False)
        
        # Display as table
        st.dataframe(
            df[['filename', 'timestamp', 'threat_level', 'threat_detected']],
            use_container_width=True
        )
        
        # Summary statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Scans", len(df))
        with col2:
            threats = len(df[df['threat_detected'] == True])
            st.metric("Threats Found", threats)
        with col3:
            if len(df) > 0:
                threat_rate = (threats / len(df)) * 100
                st.metric("Detection Rate", f"{threat_rate:.1f}%")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center;'>
        <p>🛡️ <strong>MalwareShield Pro</strong> - Advanced Threat Detection Platform</p>
        <p>Created with ❤️ by <strong>vishux777</strong></p>
        <p><small>Powered by VirusTotal API • Real-time Analysis • Zero-day Detection</small></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
