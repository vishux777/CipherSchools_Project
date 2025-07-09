import streamlit as st
import os
import hashlib
import time
import re
import io
import math
import string
import base64
from datetime import datetime
from collections import Counter
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Import custom utilities
from utils.virustotal_api import VirusTotalAPI
from utils.pdf_generator import PDFGenerator
from utils.file_analyzer import FileAnalyzer
from utils.threat_scorer import ThreatScorer

# Configure page
st.set_page_config(
    page_title="MalwareShield Pro - Advanced Malware Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
def initialize_session_state():
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'uploaded_file' not in st.session_state:
        st.session_state.uploaded_file = None
    if 'vt_results' not in st.session_state:
        st.session_state.vt_results = None
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []

def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def main():
    # Initialize session state
    initialize_session_state()
    
    # Initialize components
    vt_api = VirusTotalAPI()
    file_analyzer = FileAnalyzer()
    threat_scorer = ThreatScorer()
    pdf_generator = PDFGenerator()
    
    # Modern Professional UI Theme
    st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #cbd5e1 100%);
        color: #1e293b;
    }

    .stApp {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #cbd5e1 100%);
        color: #1e293b;
    }

    /* Modern button styling */
    .stButton > button {
        background: linear-gradient(135deg, #475569 0%, #64748b 100%);
        color: #ffffff;
        border: none;
        border-radius: 12px;
        padding: 0.8rem 2rem;
        font-weight: 600;
        font-size: 0.95rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(71, 85, 105, 0.2);
        text-transform: none;
    }

    .stButton > button:hover {
        background: linear-gradient(135deg, #334155 0%, #475569 100%);
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(71, 85, 105, 0.3);
    }

    /* Modern metric containers */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #ffffff 0%, #f1f5f9 100%);
        border: 1px solid #e2e8f0;
        padding: 1.5rem;
        border-radius: 16px;
        box-shadow: 0 4px 16px rgba(148, 163, 184, 0.1);
        transition: all 0.3s ease;
    }

    [data-testid="metric-container"]:hover {
        border-color: #cbd5e1;
        box-shadow: 0 8px 24px rgba(148, 163, 184, 0.15);
        transform: translateY(-2px);
    }

    /* Modern tabs */
    .stTabs [data-baseweb="tab-list"] {
        background: #ffffff;
        border-radius: 16px;
        padding: 0.5rem;
        border: 1px solid #e2e8f0;
        box-shadow: 0 2px 8px rgba(148, 163, 184, 0.1);
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent;
        color: #64748b;
        border-radius: 12px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
        margin: 0 0.25rem;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #475569 0%, #64748b 100%);
        color: #ffffff;
        box-shadow: 0 4px 12px rgba(71, 85, 105, 0.2);
    }

    /* Modern messages */
    .stSuccess {
        background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
        border: 1px solid #a7f3d0;
        border-radius: 12px;
        color: #065f46;
        padding: 1rem;
    }

    .stError {
        background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%);
        border: 1px solid #fca5a5;
        border-radius: 12px;
        color: #991b1b;
        padding: 1rem;
    }

    .stWarning {
        background: linear-gradient(135deg, #fffbeb 0%, #fed7aa 100%);
        border: 1px solid #fdba74;
        border-radius: 12px;
        color: #92400e;
        padding: 1rem;
    }

    .stInfo {
        background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
        border: 1px solid #93c5fd;
        border-radius: 12px;
        color: #1e40af;
        padding: 1rem;
    }

    /* Modern file uploader */
    [data-testid="stFileUploader"] {
        background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
        border: 2px dashed #cbd5e1;
        border-radius: 16px;
        padding: 3rem;
        transition: all 0.3s ease;
        text-align: center;
    }

    [data-testid="stFileUploader"]:hover {
        border-color: #94a3b8;
        background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(148, 163, 184, 0.1);
    }

    /* Modern sidebar */
    .css-1d391kg {
        background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
    }

    /* Modern dataframes */
    .stDataFrame {
        background: #ffffff;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 2px 8px rgba(148, 163, 184, 0.1);
    }

    /* Modern titles and headers */
    h1, h2, h3, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #0f172a !important;
        font-weight: 700 !important;
    }

    /* Modern progress bars */
    .stProgress .st-bo {
        background-color: #e2e8f0;
    }

    .stProgress .st-bp {
        background: linear-gradient(90deg, #475569 0%, #64748b 100%);
    }

    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.title("🛡️ MalwareShield Pro")
    st.markdown("**Advanced Malware Analysis Platform with VirusTotal Integration**")
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["📁 File Analysis", "🔍 VirusTotal Scan", "📊 Results Dashboard", "📄 Reports"])
    
    with tab1:
        handle_file_upload_and_analysis(file_analyzer, threat_scorer, vt_api)
    
    with tab2:
        st.header("🔍 VirusTotal Analysis")
        
        # Show API key status
        if vt_api.api_key and len(vt_api.api_key) >= 60:
            st.success("VirusTotal API key configured")
        else:
            st.error("VirusTotal API key not properly configured")
            st.info("Please ensure you have a valid VirusTotal API key to use this feature.")
        
        handle_virustotal_analysis(vt_api, threat_scorer)
    
    with tab3:
        display_comprehensive_results()
    
    with tab4:
        handle_report_generation(pdf_generator)

def handle_file_upload_and_analysis(file_analyzer, threat_scorer, vt_api=None):
    st.header("📁 File Upload & Static Analysis")
    
    # Sidebar configuration
    with st.sidebar:
        st.subheader("🔧 Analysis Configuration")
        
        # Analysis modules
        hash_analysis = st.checkbox("🔍 Hash Analysis", value=True)
        string_extraction = st.checkbox("📝 String Extraction", value=True)
        entropy_analysis = st.checkbox("📊 Entropy Analysis", value=True)
        pattern_detection = st.checkbox("🎯 Pattern Detection", value=True)
        file_metadata = st.checkbox("📋 File Metadata", value=True)
        
        st.divider()
        
        # Analysis settings
        st.subheader("⚙️ Settings")
        max_strings = st.slider("Max Strings to Extract", 50, 500, 100)
        min_string_length = st.slider("Min String Length", 3, 20, 5)
        
        st.divider()
        
        # System status
        st.subheader("📊 System Status")
        st.success("Static Analysis Engine: Active")
        st.success("Pattern Detection: Ready")
        if vt_api and vt_api.is_api_key_valid():
            st.success("VirusTotal API: Connected")
        else:
            st.error("VirusTotal API: Check Key")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=None,
        help="Upload any file for comprehensive malware analysis. Files are analyzed statically - no code execution."
    )
    
    if uploaded_file is not None:
        st.session_state.uploaded_file = uploaded_file
        
        # Display file information
        file_size = len(uploaded_file.getvalue())
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("📄 File Name", uploaded_file.name)
        with col2:
            st.metric("📏 File Size", format_file_size(file_size))
        with col3:
            st.metric("🗂️ File Type", uploaded_file.type or "Unknown")
        
        # Analysis control
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("🚀 Start Static Analysis", type="primary", use_container_width=True):
                run_static_analysis(
                    uploaded_file, 
                    file_analyzer,
                    threat_scorer,
                    {
                        'hash_analysis': hash_analysis,
                        'string_extraction': string_extraction,
                        'entropy_analysis': entropy_analysis,
                        'pattern_detection': pattern_detection,
                        'file_metadata': file_metadata,
                        'max_strings': max_strings,
                        'min_string_length': min_string_length
                    }
                )
        
        with col2:
            if st.button("🧹 Clear Results", use_container_width=True):
                st.session_state.analysis_results = None
                st.session_state.vt_results = None
                st.rerun()

def handle_virustotal_analysis(vt_api, threat_scorer):
    
    if st.session_state.uploaded_file is None:
        st.info("📁 Please upload a file in the File Analysis tab first.")
        return
    
    # Display file info
    file_data = st.session_state.uploaded_file.getvalue()
    file_hash = hashlib.sha256(file_data).hexdigest()
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("📄 File", st.session_state.uploaded_file.name)
    with col2:
        st.metric("🔐 SHA256", f"{file_hash[:16]}...")
    
    # VirusTotal analysis options
    st.subheader("🛠️ VirusTotal Operations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔍 Check File Hash", type="primary", use_container_width=True):
            if vt_api.is_api_key_valid():
                run_virustotal_hash_check(vt_api, file_hash, threat_scorer)
            else:
                st.error("VirusTotal API key is not configured or invalid")
    
    with col2:
        if st.button("📤 Upload & Scan File", use_container_width=True):
            if vt_api.is_api_key_valid():
                run_virustotal_file_upload(vt_api, file_data, threat_scorer)
            else:
                st.error("VirusTotal API key is not configured or invalid")
    
    # Display VirusTotal results if available
    if st.session_state.vt_results:
        display_virustotal_results(st.session_state.vt_results)

def run_static_analysis(uploaded_file, file_analyzer, threat_scorer, config):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("🔍 Starting file analysis...")
        progress_bar.progress(0.1)
        
        file_data = uploaded_file.getvalue()
        file_name = uploaded_file.name
        
        # Calculate hashes
        status_text.text("🔐 Calculating file hashes...")
        progress_bar.progress(0.2)
        hashes = file_analyzer.calculate_hashes(file_data)
        
        # Calculate entropy
        status_text.text("📊 Analyzing file entropy...")
        progress_bar.progress(0.3)
        entropy = file_analyzer.calculate_entropy(file_data)
        
        # Extract strings
        status_text.text("📝 Extracting strings...")
        progress_bar.progress(0.4)
        strings = file_analyzer.extract_strings(
            file_data, 
            max_strings=config['max_strings'],
            min_length=config['min_string_length']
        )
        
        # Detect patterns
        status_text.text("🎯 Detecting patterns...")
        progress_bar.progress(0.6)
        patterns = file_analyzer.detect_patterns(file_data)
        
        # Extract metadata
        status_text.text("📋 Extracting metadata...")
        progress_bar.progress(0.7)
        metadata = file_analyzer.extract_metadata(file_data, file_name)
        
        # Analyze suspicious patterns
        status_text.text("🚨 Analyzing suspicious patterns...")
        progress_bar.progress(0.8)
        suspicious_patterns = file_analyzer.analyze_suspicious_patterns(file_data)
        
        # Compile results
        analysis_results = {
            'file_info': {
                'name': file_name,
                'size': len(file_data),
                'type': uploaded_file.type,
                'analysis_time': datetime.now().isoformat()
            },
            'hashes': hashes,
            'entropy': entropy,
            'strings': strings,
            'patterns': patterns,
            'metadata': metadata,
            'suspicious_patterns': suspicious_patterns
        }
        
        # Calculate threat score
        status_text.text("🛡️ Calculating threat score...")
        progress_bar.progress(0.9)
        threat_score = threat_scorer.calculate_static_threat_score(analysis_results)
        analysis_results['threat_score'] = threat_score
        
        # Store results
        st.session_state.analysis_results = analysis_results
        
        # Add to history
        st.session_state.analysis_history.append({
            'timestamp': datetime.now(),
            'file_name': file_name,
            'analysis_type': 'Static Analysis',
            'threat_score': threat_score
        })
        
        progress_bar.progress(1.0)
        status_text.text("Analysis completed successfully!")
        
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        st.success("Static analysis completed successfully!")
        st.rerun()
        
    except Exception as e:
        st.error(f"Analysis failed: {str(e)}")
        progress_bar.empty()
        status_text.empty()

def run_virustotal_hash_check(vt_api, file_hash, threat_scorer):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("🔍 Checking file hash with VirusTotal...")
        progress_bar.progress(0.2)
        
        # First check if API key is configured
        if not vt_api.api_key or len(vt_api.api_key) < 60:
            progress_bar.empty()
            status_text.empty()
            st.error("VirusTotal API key is not properly configured")
            return
        
        progress_bar.progress(0.4)
        
        # Get file report
        vt_results = vt_api.get_file_report(file_hash)
        progress_bar.progress(0.7)
        
        if vt_results and 'data' in vt_results:
            # Calculate VirusTotal threat score
            vt_threat_score = threat_scorer.calculate_virustotal_threat_score(vt_results)
            vt_results['threat_score'] = vt_threat_score
            
            st.session_state.vt_results = vt_results
            
            # Add to history
            st.session_state.analysis_history.append({
                'timestamp': datetime.now(),
                'file_name': st.session_state.uploaded_file.name,
                'analysis_type': 'VirusTotal Hash Check',
                'threat_score': vt_threat_score
            })
            
            progress_bar.progress(1.0)
            status_text.text("VirusTotal hash check completed!")
            
            time.sleep(1)
            progress_bar.empty()
            status_text.empty()
            
            st.success("VirusTotal analysis completed successfully!")
            st.rerun()
        else:
            progress_bar.empty()
            status_text.empty()
            st.warning("File not found in VirusTotal database. Try uploading the file for analysis.")
            
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"VirusTotal analysis failed: {str(e)}")
        st.info("This might be due to network issues or API rate limits. Please try again in a few moments.")

def run_virustotal_file_upload(vt_api, file_data, threat_scorer):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Check file size first
        if len(file_data) > 32 * 1024 * 1024:  # 32MB limit
            progress_bar.empty()
            status_text.empty()
            st.error("File too large for VirusTotal upload (max 32MB)")
            return
        
        status_text.text("📤 Uploading file to VirusTotal...")
        progress_bar.progress(0.2)
        
        # Check if API key is configured
        if not vt_api.api_key or len(vt_api.api_key) < 60:
            progress_bar.empty()
            status_text.empty()
            st.error("VirusTotal API key is not properly configured")
            return
        
        upload_result = vt_api.upload_file(file_data)
        progress_bar.progress(0.4)
        
        if upload_result and 'data' in upload_result:
            analysis_id = upload_result['data']['id']
            
            status_text.text("⏳ Analysis submitted. Waiting for results...")
            progress_bar.progress(0.6)
            
            # Wait a bit then try to get results
            time.sleep(15)  # Wait for analysis
            
            file_hash = hashlib.sha256(file_data).hexdigest()
            vt_results = vt_api.get_file_report(file_hash)
            
            if vt_results and 'data' in vt_results:
                vt_threat_score = threat_scorer.calculate_virustotal_threat_score(vt_results)
                vt_results['threat_score'] = vt_threat_score
                
                st.session_state.vt_results = vt_results
                
                progress_bar.progress(1.0)
                status_text.text("File upload and analysis completed!")
                
                time.sleep(1)
                progress_bar.empty()
                status_text.empty()
                
                st.success("File uploaded and analyzed successfully!")
                st.rerun()
            else:
                progress_bar.empty()
                status_text.empty()
                st.warning("Analysis is still in progress. The file has been submitted successfully. Results may take a few minutes to appear.")
        else:
            progress_bar.empty()
            status_text.empty()
            st.error("Failed to upload file to VirusTotal. Please check your API key and try again.")
            
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"File upload failed: {str(e)}")
        st.info("This might be due to network issues, file size limits, or API rate limits.")

def display_comprehensive_results():
    st.header("📊 Comprehensive Analysis Results")
    
    if st.session_state.analysis_results is None and st.session_state.vt_results is None:
        st.info("🔍 No analysis results available. Please run an analysis first.")
        return
    
    # Create result tabs
    if st.session_state.analysis_results and st.session_state.vt_results:
        result_tabs = st.tabs(["🛡️ Threat Summary", "🔍 Static Analysis", "🌐 VirusTotal Results", "📈 Detailed Metrics"])
    elif st.session_state.analysis_results:
        result_tabs = st.tabs(["🛡️ Threat Summary", "🔍 Static Analysis", "📈 Detailed Metrics"])
    elif st.session_state.vt_results:
        result_tabs = st.tabs(["🛡️ Threat Summary", "🌐 VirusTotal Results"])
    else:
        return
    
    # Threat Summary Tab
    with result_tabs[0]:
        display_threat_summary()
    
    # Static Analysis Tab (if available)
    if st.session_state.analysis_results:
        with result_tabs[1]:
            display_static_analysis_results()
    
    # VirusTotal Results Tab (if available)
    if st.session_state.vt_results:
        tab_index = 2 if st.session_state.analysis_results else 1
        with result_tabs[tab_index]:
            display_virustotal_results(st.session_state.vt_results)
    
    # Detailed Metrics Tab
    if st.session_state.analysis_results:
        tab_index = 3 if st.session_state.vt_results else 2
        with result_tabs[tab_index]:
            display_detailed_metrics()

def display_threat_summary():
    st.subheader("🛡️ Overall Threat Assessment")
    
    # Calculate combined threat score
    static_score = 0
    vt_score = 0
    
    if st.session_state.analysis_results:
        static_score = st.session_state.analysis_results['threat_score']['overall_score']
    
    if st.session_state.vt_results:
        vt_score = st.session_state.vt_results['threat_score']['overall_score']
    
    # Weight the scores (static analysis 40%, VirusTotal 60%)
    if static_score > 0 and vt_score > 0:
        combined_score = (static_score * 0.4) + (vt_score * 0.6)
    elif static_score > 0:
        combined_score = static_score
    elif vt_score > 0:
        combined_score = vt_score
    else:
        combined_score = 0
    
    # Display combined threat gauge
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = combined_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Combined Threat Score"},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "#dc2626" if combined_score >= 70 else "#f59e0b" if combined_score >= 40 else "#059669"},
            'steps': [
                {'range': [0, 40], 'color': "#f0fdf4"},
                {'range': [40, 70], 'color': "#fef3c7"},
                {'range': [70, 100], 'color': "#fee2e2"}
            ],
            'threshold': {
                'line': {'color': "#64748b", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))
    
    fig.update_layout(height=400, showlegend=False)
    st.plotly_chart(fig, use_container_width=True, key="combined_threat_gauge")
    
    # Threat level interpretation
    if combined_score >= 70:
        st.error("🚨 HIGH THREAT - Immediate attention required")
        st.markdown("This file shows strong indicators of malicious behavior.")
    elif combined_score >= 40:
        st.warning("⚠️ MEDIUM THREAT - Exercise caution")
        st.markdown("This file shows some suspicious characteristics that warrant further investigation.")
    else:
        st.success("✅ LOW THREAT - File appears safe")
        st.markdown("This file shows minimal indicators of malicious behavior.")
    
    # Component scores breakdown
    col1, col2 = st.columns(2)
    
    with col1:
        if st.session_state.analysis_results:
            st.metric("Static Analysis Score", f"{static_score:.1f}/100")
        else:
            st.metric("Static Analysis Score", "Not Available")
    
    with col2:
        if st.session_state.vt_results:
            st.metric("VirusTotal Score", f"{vt_score:.1f}/100")
        else:
            st.metric("VirusTotal Score", "Not Available")

def display_static_analysis_results():
    st.subheader("🔍 Static Analysis Results")
    
    if not st.session_state.analysis_results:
        st.error("No static analysis results available")
        return
    
    results = st.session_state.analysis_results
    
    # File entropy gauge
    if 'entropy' in results:
        entropy_value = results['entropy']
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = entropy_value,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "File Entropy"},
                gauge = {
                    'axis': {'range': [None, 8]},
                    'bar': {'color': "#059669" if entropy_value < 6 else "#f59e0b" if entropy_value < 7 else "#dc2626"},
                    'steps': [
                        {'range': [0, 6], 'color': "#f0fdf4"},
                        {'range': [6, 7], 'color': "#fef3c7"},
                        {'range': [7, 8], 'color': "#fee2e2"}
                    ]
                }
            ))
            fig.update_layout(height=300, showlegend=False)
            st.plotly_chart(fig, use_container_width=True, key="entropy_gauge")
        
        with col2:
            st.write("**Entropy Analysis:**")
            if entropy_value < 6:
                st.success("Low entropy - File appears uncompressed/unencrypted")
            elif entropy_value < 7:
                st.warning("Medium entropy - File may be compressed or partially encrypted")
            else:
                st.error("High entropy - File is likely compressed, encrypted, or packed")
            
            st.write(f"**Entropy Value:** {entropy_value:.3f}")
            st.write("**Scale:** 0 (completely predictable) to 8 (completely random)")
    
    # File hashes
    if 'hashes' in results:
        st.subheader("🔐 File Hashes")
        hash_data = results['hashes']
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.code(f"MD5:\n{hash_data['md5']}")
        with col2:
            st.code(f"SHA1:\n{hash_data['sha1']}")
        with col3:
            st.code(f"SHA256:\n{hash_data['sha256']}")
    
    # Strings analysis
    if 'strings' in results and results['strings']:
        st.subheader("📝 Extracted Strings")
        strings_df = pd.DataFrame({'Strings': results['strings'][:20]})  # Show first 20
        st.dataframe(strings_df, use_container_width=True)
        
        if len(results['strings']) > 20:
            st.info(f"Showing first 20 of {len(results['strings'])} extracted strings")
    
    # Pattern detection
    if 'patterns' in results:
        st.subheader("🎯 Pattern Detection")
        patterns = results['patterns']
        
        pattern_summary = []
        for pattern_type, matches in patterns.items():
            if matches:
                pattern_summary.append({
                    'Pattern Type': pattern_type.replace('_', ' ').title(),
                    'Count': len(matches),
                    'Examples': ', '.join(matches[:3]) if len(matches) <= 3 else ', '.join(matches[:3]) + '...'
                })
        
        if pattern_summary:
            pattern_df = pd.DataFrame(pattern_summary)
            st.dataframe(pattern_df, use_container_width=True)
        else:
            st.info("No suspicious patterns detected")

def display_virustotal_results(vt_results):
    if not vt_results or 'data' not in vt_results:
        st.error("No VirusTotal results available")
        return
    
    data = vt_results['data']['attributes']
    
    st.subheader("🌐 VirusTotal Analysis Results")
    
    # Detection statistics
    stats = data.get('last_analysis_stats', {})
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🔴 Malicious", stats.get('malicious', 0))
    with col2:
        st.metric("⚠️ Suspicious", stats.get('suspicious', 0))
    with col3:
        st.metric("✅ Clean", stats.get('harmless', 0))
    with col4:
        st.metric("❓ Undetected", stats.get('undetected', 0))
    
    # Detection pie chart
    if stats:
        fig = px.pie(
            values=list(stats.values()),
            names=list(stats.keys()),
            title="Detection Results Distribution",
            color_discrete_map={
                'malicious': '#dc2626',
                'suspicious': '#f59e0b',
                'harmless': '#059669',
                'undetected': '#6b7280'
            }
        )
        st.plotly_chart(fig, use_container_width=True, key="vt_detection_pie")
    
    # Detailed engine results
    st.subheader("🔍 Engine Detection Details")
    
    results = data.get('last_analysis_results', {})
    if results:
        engine_data = []
        for engine, result in results.items():
            engine_data.append({
                'Engine': engine,
                'Result': result.get('result', 'Clean'),
                'Category': result.get('category', 'undetected'),
                'Version': result.get('version', 'Unknown')
            })
        
        engine_df = pd.DataFrame(engine_data)
        
        # Filter options
        filter_option = st.selectbox(
            "Filter by category:",
            ["All", "malicious", "suspicious", "harmless", "undetected"]
        )
        
        if filter_option != "All":
            filtered_df = engine_df[engine_df['Category'] == filter_option]
        else:
            filtered_df = engine_df
        
        st.dataframe(filtered_df, use_container_width=True)

def display_detailed_metrics():
    st.subheader("📈 Detailed Analysis Metrics")
    
    if not st.session_state.analysis_results:
        st.info("No static analysis metrics available")
        return
    
    results = st.session_state.analysis_results
    
    # Create metrics dashboard
    col1, col2 = st.columns(2)
    
    with col1:
        # File size analysis
        file_size = results['file_info']['size']
        st.metric("File Size", format_file_size(file_size))
        
        # String analysis metrics
        if 'strings' in results:
            strings_count = len(results['strings'])
            st.metric("Extracted Strings", strings_count)
        
        # Pattern metrics
        if 'patterns' in results:
            patterns = results['patterns']
            total_patterns = sum(len(v) for v in patterns.values())
            st.metric("Total Patterns", total_patterns)
    
    with col2:
        # Entropy metrics
        if 'entropy' in results:
            entropy = results['entropy']
            st.metric("File Entropy", f"{entropy:.3f}")
        
        # Hash metrics
        if 'hashes' in results:
            st.metric("Hash Algorithms", "3 (MD5, SHA1, SHA256)")
        
        # Analysis time
        analysis_time = datetime.fromisoformat(results['file_info']['analysis_time'])
        st.metric("Analysis Time", analysis_time.strftime("%H:%M:%S"))

def handle_report_generation(pdf_generator):
    st.header("📄 Analysis Reports")
    
    if st.session_state.analysis_results is None and st.session_state.vt_results is None:
        st.info("📋 No analysis data available for report generation.")
        return
    
    st.subheader("📊 Report Options")
    
    # Report configuration
    col1, col2 = st.columns(2)
    
    with col1:
        include_static = st.checkbox("Include Static Analysis", value=bool(st.session_state.analysis_results))
        include_virustotal = st.checkbox("Include VirusTotal Results", value=bool(st.session_state.vt_results))
    
    with col2:
        include_charts = st.checkbox("Include Charts & Graphs", value=True)
        include_raw_data = st.checkbox("Include Raw Data", value=False)
    
    # Generate report
    if st.button("📄 Generate PDF Report", type="primary", use_container_width=True):
        generate_pdf_report(
            pdf_generator,
            {
                'include_static': include_static,
                'include_virustotal': include_virustotal,
                'include_charts': include_charts,
                'include_raw_data': include_raw_data
            }
        )

def generate_pdf_report(pdf_generator, options):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("📄 Generating PDF report...")
        progress_bar.progress(0.3)
        
        # Collect all data for the report
        report_data = {
            'file_info': None,
            'static_results': None,
            'vt_results': None,
            'options': options
        }
        
        if st.session_state.uploaded_file:
            report_data['file_info'] = {
                'name': st.session_state.uploaded_file.name,
                'size': len(st.session_state.uploaded_file.getvalue()),
                'type': st.session_state.uploaded_file.type
            }
        
        if options['include_static'] and st.session_state.analysis_results:
            report_data['static_results'] = st.session_state.analysis_results
        
        if options['include_virustotal'] and st.session_state.vt_results:
            report_data['vt_results'] = st.session_state.vt_results
        
        progress_bar.progress(0.6)
        
        # Generate PDF
        pdf_buffer = pdf_generator.generate_report(report_data)
        
        progress_bar.progress(0.9)
        
        if pdf_buffer:
            # Create download button
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"malware_analysis_report_{timestamp}.pdf"
            
            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_buffer.getvalue(),
                file_name=filename,
                mime="application/pdf",
                use_container_width=True
            )
            
            progress_bar.progress(1.0)
            status_text.text("PDF report generated successfully!")
            
            time.sleep(1)
            progress_bar.empty()
            status_text.empty()
            
            st.success("PDF report is ready for download!")
        else:
            progress_bar.empty()
            status_text.empty()
            st.error("Failed to generate PDF report")
            
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"Report generation failed: {str(e)}")

if __name__ == "__main__":
    main()