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
    
    # Header
    st.title("🛡️ MalwareShield Pro")
    st.markdown("**Advanced Malware Analysis Platform with VirusTotal Integration**")
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["📁 File Analysis", "🔍 VirusTotal Scan", "📊 Results Dashboard", "📄 Reports"])
    
    with tab1:
        handle_file_upload_and_analysis(file_analyzer, threat_scorer)
    
    with tab2:
        handle_virustotal_analysis(vt_api, threat_scorer)
    
    with tab3:
        display_comprehensive_results()
    
    with tab4:
        handle_report_generation(pdf_generator)

def handle_file_upload_and_analysis(file_analyzer, threat_scorer):
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
        st.success("✅ Static Analysis Engine: Active")
        st.success("✅ Pattern Detection: Ready")
        if vt_api.is_api_key_valid():
            st.success("✅ VirusTotal API: Connected")
        else:
            st.error("❌ VirusTotal API: Check Key")
    
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
    st.header("🔍 VirusTotal Analysis")
    
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
                st.error("❌ VirusTotal API key is not configured or invalid")
    
    with col2:
        if st.button("📤 Upload & Scan File", use_container_width=True):
            if vt_api.is_api_key_valid():
                run_virustotal_file_upload(vt_api, file_data, threat_scorer)
            else:
                st.error("❌ VirusTotal API key is not configured or invalid")
    
    # Display VirusTotal results if available
    if st.session_state.vt_results:
        display_virustotal_results(st.session_state.vt_results)

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

def run_static_analysis(uploaded_file, file_analyzer, threat_scorer, config):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        results = {}
        file_data = uploaded_file.getvalue()
        file_name = uploaded_file.name
        
        total_steps = sum([
            config['hash_analysis'],
            config['string_extraction'],
            config['entropy_analysis'],
            config['pattern_detection'],
            config['file_metadata']
        ])
        
        current_step = 0
        
        # Hash Analysis
        if config['hash_analysis']:
            status_text.text("🔍 Calculating file hashes...")
            results['hashes'] = file_analyzer.calculate_hashes(file_data)
            current_step += 1
            progress_bar.progress(current_step / total_steps)
            time.sleep(0.3)
        
        # String Extraction
        if config['string_extraction']:
            status_text.text("📝 Extracting strings...")
            results['strings'] = file_analyzer.extract_strings(
                file_data, 
                config['max_strings'], 
                config['min_string_length']
            )
            current_step += 1
            progress_bar.progress(current_step / total_steps)
            time.sleep(0.3)
        
        # Entropy Analysis
        if config['entropy_analysis']:
            status_text.text("📊 Calculating entropy...")
            results['entropy'] = file_analyzer.calculate_entropy(file_data)
            current_step += 1
            progress_bar.progress(current_step / total_steps)
            time.sleep(0.3)
        
        # Pattern Detection
        if config['pattern_detection']:
            status_text.text("🎯 Detecting patterns...")
            results['patterns'] = file_analyzer.detect_patterns(file_data)
            current_step += 1
            progress_bar.progress(current_step / total_steps)
            time.sleep(0.3)
        
        # File Metadata
        if config['file_metadata']:
            status_text.text("📋 Extracting metadata...")
            results['metadata'] = file_analyzer.extract_metadata(file_data, file_name)
            current_step += 1
            progress_bar.progress(current_step / total_steps)
            time.sleep(0.3)
        
        # Calculate threat score
        results['threat_score'] = threat_scorer.calculate_static_threat_score(results)
        
        # Store results
        results['file_info'] = {
            'name': file_name,
            'size': len(file_data),
            'analysis_time': datetime.now().isoformat()
        }
        
        st.session_state.analysis_results = results
        
        progress_bar.progress(1.0)
        status_text.text("✅ Static analysis completed successfully!")
        
        # Add to history
        st.session_state.analysis_history.append({
            'timestamp': datetime.now(),
            'file_name': file_name,
            'analysis_type': 'Static',
            'threat_score': results['threat_score']
        })
        
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        st.success("🎉 Static analysis completed successfully!")
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Analysis failed: {str(e)}")
        progress_bar.empty()
        status_text.empty()

def run_virustotal_hash_check(vt_api, file_hash, threat_scorer):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("🔍 Checking file hash with VirusTotal...")
        progress_bar.progress(0.3)
        
        vt_results = vt_api.get_file_report(file_hash)
        progress_bar.progress(0.8)
        
        if vt_results:
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
            status_text.text("✅ VirusTotal hash check completed!")
            
            time.sleep(1)
            progress_bar.empty()
            status_text.empty()
            
            st.success("🎉 VirusTotal analysis completed!")
        else:
            progress_bar.empty()
            status_text.empty()
            st.warning("⚠️ File not found in VirusTotal database. Consider uploading for analysis.")
            
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ VirusTotal analysis failed: {str(e)}")

def run_virustotal_file_upload(vt_api, file_data, threat_scorer):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("📤 Uploading file to VirusTotal...")
        progress_bar.progress(0.2)
        
        upload_result = vt_api.upload_file(file_data)
        progress_bar.progress(0.5)
        
        if upload_result and 'data' in upload_result:
            analysis_id = upload_result['data']['id']
            
            status_text.text("⏳ Waiting for analysis to complete...")
            progress_bar.progress(0.7)
            
            # Poll for results (simplified - in production, implement proper polling)
            time.sleep(10)  # Wait for analysis
            
            file_hash = hashlib.sha256(file_data).hexdigest()
            vt_results = vt_api.get_file_report(file_hash)
            
            if vt_results:
                vt_threat_score = threat_scorer.calculate_virustotal_threat_score(vt_results)
                vt_results['threat_score'] = vt_threat_score
                
                st.session_state.vt_results = vt_results
                
                progress_bar.progress(1.0)
                status_text.text("✅ File upload and analysis completed!")
                
                time.sleep(1)
                progress_bar.empty()
                status_text.empty()
                
                st.success("🎉 File uploaded and analyzed successfully!")
            else:
                progress_bar.empty()
                status_text.empty()
                st.warning("⚠️ Analysis is still in progress. Please check again later.")
        else:
            progress_bar.empty()
            status_text.empty()
            st.error("❌ Failed to upload file to VirusTotal")
            
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ File upload failed: {str(e)}")

def display_threat_summary():
    st.subheader("🛡️ Overall Threat Assessment")
    
    # Combine threat scores
    static_score = 0
    vt_score = 0
    
    if st.session_state.analysis_results:
        static_score = st.session_state.analysis_results.get('threat_score', {}).get('score', 0)
    
    if st.session_state.vt_results:
        vt_score = st.session_state.vt_results.get('threat_score', {}).get('score', 0)
    
    # Calculate combined score
    if static_score > 0 and vt_score > 0:
        combined_score = max(static_score, vt_score)  # Take the higher score
        combined_level = "High" if combined_score >= 70 else "Medium" if combined_score >= 40 else "Low"
    elif static_score > 0:
        combined_score = static_score
        combined_level = "High" if combined_score >= 70 else "Medium" if combined_score >= 40 else "Low"
    elif vt_score > 0:
        combined_score = vt_score
        combined_level = "High" if combined_score >= 70 else "Medium" if combined_score >= 40 else "Low"
    else:
        combined_score = 0
        combined_level = "Unknown"
    
    # Display threat level
    col1, col2, col3 = st.columns(3)
    
    with col1:
        threat_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢", "Unknown": "⚪"}
        st.metric(
            "🚨 Threat Level",
            f"{threat_color.get(combined_level, '⚪')} {combined_level}",
            f"Score: {combined_score}/100"
        )
    
    with col2:
        if st.session_state.analysis_results:
            st.metric("📊 Static Analysis", f"Score: {static_score}/100")
        else:
            st.metric("📊 Static Analysis", "Not Available")
    
    with col3:
        if st.session_state.vt_results:
            detections = st.session_state.vt_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = detections.get('malicious', 0)
            total = sum(detections.values()) if detections else 0
            st.metric("🌐 VirusTotal", f"{malicious}/{total} detections")
        else:
            st.metric("🌐 VirusTotal", "Not Available")
    
    # Threat gauge
    if combined_score > 0:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=combined_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Combined Threat Score"},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "red" if combined_score >= 70 else "orange" if combined_score >= 40 else "green"},
                'steps': [
                    {'range': [0, 40], 'color': "lightgreen"},
                    {'range': [40, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 70
                }
            }
        ))
        
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)

def display_static_analysis_results():
    if not st.session_state.analysis_results:
        return
    
    results = st.session_state.analysis_results
    
    # Create tabs for different analysis types
    analysis_tabs = st.tabs(["🔐 Hashes", "📝 Strings", "📊 Entropy", "🎯 Patterns", "📋 Metadata"])
    
    # Hash Analysis Tab
    with analysis_tabs[0]:
        if 'hashes' in results:
            st.subheader("🔐 Cryptographic Hashes")
            hash_data = results['hashes']
            
            hash_df = pd.DataFrame([
                {"Algorithm": "MD5", "Hash": hash_data['md5']},
                {"Algorithm": "SHA1", "Hash": hash_data['sha1']},
                {"Algorithm": "SHA256", "Hash": hash_data['sha256']}
            ])
            
            st.dataframe(hash_df, use_container_width=True)
    
    # String Analysis Tab
    with analysis_tabs[1]:
        if 'strings' in results:
            strings_data = results['strings']
            st.subheader(f"📝 Extracted Strings ({len(strings_data)} found)")
            
            if strings_data:
                # String statistics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Strings", len(strings_data))
                with col2:
                    avg_length = sum(len(s) for s in strings_data) / len(strings_data)
                    st.metric("Average Length", f"{avg_length:.1f}")
                with col3:
                    max_length = max(len(s) for s in strings_data)
                    st.metric("Max Length", max_length)
                
                # Display strings
                strings_df = pd.DataFrame({
                    "String": strings_data[:50],
                    "Length": [len(s) for s in strings_data[:50]]
                })
                st.dataframe(strings_df, use_container_width=True)
    
    # Entropy Analysis Tab
    with analysis_tabs[2]:
        if 'entropy' in results:
            entropy_value = results['entropy']
            st.subheader("📊 File Entropy Analysis")
            
            # Entropy gauge
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=entropy_value,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "File Entropy"},
                gauge={
                    'axis': {'range': [None, 8]},
                    'bar': {'color': "green" if entropy_value < 6 else "orange" if entropy_value < 7 else "red"},
                    'steps': [
                        {'range': [0, 6], 'color': "lightgreen"},
                        {'range': [6, 7], 'color': "yellow"},
                        {'range': [7, 8], 'color': "red"}
                    ]
                }
            ))
            
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
            
            # Entropy interpretation
            if entropy_value > 7:
                st.error("⚠️ Very high entropy - possible encryption/compression/packing")
            elif entropy_value > 6:
                st.warning("⚠️ High entropy - potentially suspicious")
            else:
                st.success("✅ Normal entropy levels")
    
    # Pattern Detection Tab
    with analysis_tabs[3]:
        if 'patterns' in results:
            patterns_data = results['patterns']
            st.subheader("🎯 Detected Patterns")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write("**🌐 URLs Found:**")
                if patterns_data.get('urls'):
                    for url in patterns_data['urls']:
                        st.code(url)
                else:
                    st.info("No URLs detected")
            
            with col2:
                st.write("**🌍 IP Addresses:**")
                if patterns_data.get('ips'):
                    for ip in patterns_data['ips']:
                        st.code(ip)
                else:
                    st.info("No IP addresses detected")
            
            with col3:
                st.write("**📧 Email Addresses:**")
                if patterns_data.get('emails'):
                    for email in patterns_data['emails']:
                        st.code(email)
                else:
                    st.info("No email addresses detected")
    
    # Metadata Tab
    with analysis_tabs[4]:
        if 'metadata' in results:
            metadata = results['metadata']
            st.subheader("📋 File Metadata")
            
            metadata_df = pd.DataFrame([
                {"Property": key, "Value": str(value)}
                for key, value in metadata.items()
            ])
            
            st.dataframe(metadata_df, use_container_width=True)

def display_virustotal_results(vt_results):
    if not vt_results or 'data' not in vt_results:
        st.error("❌ No VirusTotal results available")
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
                'malicious': '#ff4444',
                'suspicious': '#ffaa00',
                'harmless': '#44ff44',
                'undetected': '#888888'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    
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
            status_text.text("✅ PDF report generated successfully!")
            
            time.sleep(1)
            progress_bar.empty()
            status_text.empty()
            
            st.success("🎉 PDF report is ready for download!")
        else:
            progress_bar.empty()
            status_text.empty()
            st.error("❌ Failed to generate PDF report")
            
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ Report generation failed: {str(e)}")

if __name__ == "__main__":
    main()
