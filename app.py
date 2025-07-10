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
from utils.virustotal import VirusTotalAPI
from utils.report_generator import ReportGenerator
from utils.analysis_engine import AnalysisEngine

# Configure page
st.set_page_config(
    page_title="MalwareShield Pro - Advanced Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
# Load custom CSS
def load_css():
    try:
        with open("assets/custom_styles.css", "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        # Fallback CSS if file doesn't exist
        st.markdown("""
        <style>
        .animated-header {
            background: linear-gradient(135deg, #0f4c75, #3282b8, #bbe1fa);
            padding: 2rem;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 2rem;
        }
        .header-title {
            font-size: 3rem;
            font-weight: bold;
            color: white;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header-subtitle {
            font-size: 1.2rem;
            color: #e8f4f8;
        }
        </style>
        """, unsafe_allow_html=True)

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

def main():
    # Load custom styling
    load_css()
    
    # Initialize session state
    init_session_state()
    
    # Initialize components
    vt_api = VirusTotalAPI(st.session_state.vt_api_key)
    analysis_engine = AnalysisEngine()
    report_generator = ReportGenerator()
    
    # Header with enhanced animations
    st.markdown("""
    <div class="animated-header">
        <div class="header-container">
            <div class="header-title">🛡️ MALWARESHIELD PRO</div>
            <div class="header-subtitle">
                Advanced Multi-Engine Threat Detection System
                <br>
                <span class="feature-highlight">Now with VirusTotal Integration</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Real-time status indicators
    display_system_status()

    # Sidebar configuration
    with st.sidebar:
        st.markdown("""
        <div class="sidebar-header">
            <h3>🔧 Analysis Configuration</h3>
        </div>
        """, unsafe_allow_html=True)

        # VirusTotal API Key configuration
        st.markdown("#### 🔑 VirusTotal API")
        api_key_input = st.text_input(
            "API Key", 
            value=st.session_state.vt_api_key,
            type="password",
            help="Enter your VirusTotal API key for enhanced scanning"
        )
        
        if api_key_input != st.session_state.vt_api_key:
            st.session_state.vt_api_key = api_key_input
            vt_api = VirusTotalAPI(api_key_input)

        # Analysis modules with enhanced UI
        st.markdown("#### 🎯 Analysis Modules")
        
        col1, col2 = st.columns(2)
        with col1:
            hash_analysis = st.checkbox("🔍 Hash Analysis", value=True)
            entropy_analysis = st.checkbox("📊 Entropy Analysis", value=True)
            vt_scan = st.checkbox("🌐 VirusTotal Scan", value=bool(st.session_state.vt_api_key))
        
        with col2:
            string_extraction = st.checkbox("📝 String Extraction", value=True)
            pattern_detection = st.checkbox("🎯 Pattern Detection", value=True)
            behavioral_analysis = st.checkbox("🧠 Behavioral Analysis", value=True)

        st.markdown("---")

        # Advanced settings
        st.markdown("#### ⚙️ Advanced Settings")
        max_strings = st.slider("Max Strings to Extract", 50, 1000, 200)
        min_string_length = st.slider("Min String Length", 3, 20, 5)
        sensitivity_level = st.selectbox("Detection Sensitivity", ["Low", "Medium", "High"], index=1)

        st.markdown("---")
        
        # Quick stats
        display_sidebar_stats()

    # Main content area with enhanced layout
    col1, col2 = st.columns([2, 1])

    with col1:
        # Enhanced file upload section
        st.markdown("""
        <div class="upload-section">
            <h3>📁 File Upload & Analysis</h3>
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Drag and drop your file here or click to browse",
            type=None,
            help="Upload any file for comprehensive malware analysis. Maximum file size: 32MB"
        )

        if uploaded_file is not None:
            st.session_state.uploaded_file = uploaded_file
            display_file_info(uploaded_file)

    with col2:
        # Enhanced statistics panel
        st.markdown("""
        <div class="stats-panel">
            <h3>📈 Real-time Statistics</h3>
        </div>
        """, unsafe_allow_html=True)
        
        display_analysis_stats()

    # Analysis control section
    if uploaded_file is not None:
        st.markdown("---")
        display_analysis_controls(
            uploaded_file, vt_api, analysis_engine, report_generator,
            {
                'hash_analysis': hash_analysis,
                'string_extraction': string_extraction,
                'entropy_analysis': entropy_analysis,
                'pattern_detection': pattern_detection,
                'vt_scan': vt_scan,
                'behavioral_analysis': behavioral_analysis,
                'max_strings': max_strings,
                'min_string_length': min_string_length,
                'sensitivity_level': sensitivity_level
            }
        )

    # Results display
    if st.session_state.analysis_results:
        st.markdown("---")
        display_enhanced_results(st.session_state.analysis_results, report_generator)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div class="footer">
        <div class="footer-content">
            <p>🛡️ <strong>MalwareShield Pro</strong> - Advanced Threat Detection Platform</p>
            <p>Created with ❤️ by <strong>vishux777</strong></p>
            <p><small>Powered by VirusTotal API • Real-time Analysis • Zero-day Detection</small></p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def display_system_status():
    """Display real-time system status indicators"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "🔧 Analysis Engine", 
            "Online", 
            delta="✅ Ready",
            delta_color="normal"
        )
    
    with col2:
        vt_status = "Connected" if st.session_state.vt_api_key else "Offline"
        vt_delta = "🌐 API Active" if st.session_state.vt_api_key else "❌ No API Key"
        st.metric(
            "🌍 VirusTotal", 
            vt_status, 
            delta=vt_delta,
            delta_color="normal" if st.session_state.vt_api_key else "inverse"
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
    
    st.markdown(f"""
    <div class="file-info-card">
        <div class="file-info-header">
            <h4>📄 File Information</h4>
        </div>
        <div class="file-info-content">
            <div class="info-row">
                <span class="info-label">📝 Name:</span>
                <span class="info-value">{uploaded_file.name}</span>
            </div>
            <div class="info-row">
                <span class="info-label">📏 Size:</span>
                <span class="info-value">{format_file_size(file_size)}</span>
            </div>
            <div class="info-row">
                <span class="info-label">🏷️ Type:</span>
                <span class="info-value">{file_type}</span>
            </div>
            <div class="info-row">
                <span class="info-label">⏰ Uploaded:</span>
                <span class="info-value">{datetime.now().strftime('%H:%M:%S')}</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def display_analysis_stats():
    """Display analysis statistics panel"""
    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        # Threat level with color coding
        threat_level = results.get('threat_assessment', {}).get('level', 'Unknown')
        threat_color = get_threat_color(threat_level)
        
        st.markdown(f"""
        <div class="threat-indicator">
            <div class="threat-level" style="color: {threat_color};">
                {threat_level.upper()}
            </div>
            <div class="threat-subtitle">Threat Level</div>
        </div>
        """, unsafe_allow_html=True)
        
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
        
        # VirusTotal results
        if 'virustotal' in results:
            vt_data = results['virustotal']
            if 'stats' in vt_data:
                stats = vt_data['stats']
                st.metric(
                    "VT Detection", 
                    f"{stats['malicious']}/{stats['total']}",
                    delta=f"{stats['malicious']} engines flagged"
                )
    else:
        st.info("📊 Upload a file to see analysis statistics")

def display_analysis_controls(uploaded_file, vt_api, analysis_engine, report_generator, config):
    """Display enhanced analysis control interface"""
    st.markdown("""
    <div class="analysis-controls">
        <h3>🚀 Analysis Control Center</h3>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        if st.button("🔍 Start Comprehensive Analysis", type="primary", use_container_width=True):
            run_enhanced_analysis(uploaded_file, vt_api, analysis_engine, config)

    with col2:
        if st.button("📊 Quick Scan", use_container_width=True):
            run_quick_analysis(uploaded_file, analysis_engine, config)

    with col3:
        if st.button("🧹 Clear Results", use_container_width=True):
            st.session_state.analysis_results = None
            st.rerun()

    # Download reports section
    if st.session_state.analysis_results:
        st.markdown("### 📥 Download Reports")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📄 Download PDF Report", use_container_width=True):
                pdf_data = report_generator.generate_pdf_report(st.session_state.analysis_results)
                st.download_button(
                    label="💾 Save PDF",
                    data=pdf_data,
                    file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
        
        with col2:
            if st.button("📋 Download JSON Report", use_container_width=True):
                json_data = report_generator.generate_json_report(st.session_state.analysis_results)
                st.download_button(
                    label="💾 Save JSON",
                    data=json_data,
                    file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col3:
            if st.button("📊 Download CSV Report", use_container_width=True):
                csv_data = report_generator.generate_csv_report(st.session_state.analysis_results)
                st.download_button(
                    label="💾 Save CSV",
                    data=csv_data,
                    file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

def run_enhanced_analysis(uploaded_file, vt_api, analysis_engine, config):
    """Run comprehensive analysis with all modules"""
    progress_container = st.container()
    
    with progress_container:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            results = {}
            file_data = uploaded_file.getvalue()
            file_name = uploaded_file.name
            
            # Calculate total steps
            total_steps = sum([
                config['hash_analysis'],
                config['string_extraction'],
                config['entropy_analysis'],
                config['pattern_detection'],
                config['vt_scan'] and bool(st.session_state.vt_api_key),
                config['behavioral_analysis']
            ])
            
            current_step = 0
            
            # Hash Analysis
            if config['hash_analysis']:
                status_text.markdown("🔍 **Calculating cryptographic hashes...**")
                results['hashes'] = analysis_engine.calculate_hashes(file_data)
                current_step += 1
                progress_bar.progress(current_step / total_steps)
                time.sleep(0.5)
            
            # String Extraction
            if config['string_extraction']:
                status_text.markdown("📝 **Extracting readable strings...**")
                results['strings'] = analysis_engine.extract_strings(
                    file_data, config['max_strings'], config['min_string_length']
                )
                current_step += 1
                progress_bar.progress(current_step / total_steps)
                time.sleep(0.5)
            
            # Entropy Analysis
            if config['entropy_analysis']:
                status_text.markdown("📊 **Analyzing file entropy...**")
                results['entropy'] = analysis_engine.calculate_entropy(file_data)
                current_step += 1
                progress_bar.progress(current_step / total_steps)
                time.sleep(0.5)
            
            # Pattern Detection
            if config['pattern_detection']:
                status_text.markdown("🎯 **Detecting suspicious patterns...**")
                results['patterns'] = analysis_engine.detect_patterns(file_data)
                current_step += 1
                progress_bar.progress(current_step / total_steps)
                time.sleep(0.5)
            
            # VirusTotal Scan
            if config['vt_scan'] and st.session_state.vt_api_key:
                status_text.markdown("🌐 **Scanning with VirusTotal...**")
                results['virustotal'] = vt_api.scan_file(file_data, file_name)
                current_step += 1
                progress_bar.progress(current_step / total_steps)
                time.sleep(1.0)
            
            # Behavioral Analysis
            if config['behavioral_analysis']:
                status_text.markdown("🧠 **Performing behavioral analysis...**")
                results['behavioral'] = analysis_engine.behavioral_analysis(file_data)
                current_step += 1
                progress_bar.progress(current_step / total_steps)
                time.sleep(0.5)
            
            # Threat Assessment
            status_text.markdown("⚠️ **Calculating threat assessment...**")
            results['threat_assessment'] = analysis_engine.calculate_threat_assessment(results)
            
            # File metadata
            results['file_info'] = {
                'name': file_name,
                'size': len(file_data),
                'analysis_time': datetime.now().isoformat(),
                'config': config
            }
            
            # Store results
            st.session_state.analysis_results = results
            st.session_state.scan_history.append(results)
            
            progress_bar.progress(1.0)
            status_text.markdown("✅ **Analysis completed successfully!**")
            
            time.sleep(1)
            progress_bar.empty()
            status_text.empty()
            
            st.success("🎉 Comprehensive analysis completed!")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            progress_bar.empty()
            status_text.empty()

def run_quick_analysis(uploaded_file, analysis_engine, config):
    """Run quick analysis with essential modules only"""
    with st.spinner("⚡ Running quick analysis..."):
        try:
            results = {}
            file_data = uploaded_file.getvalue()
            
            # Essential analysis only
            results['hashes'] = analysis_engine.calculate_hashes(file_data)
            results['entropy'] = analysis_engine.calculate_entropy(file_data)
            results['threat_assessment'] = analysis_engine.calculate_threat_assessment(results)
            
            results['file_info'] = {
                'name': uploaded_file.name,
                'size': len(file_data),
                'analysis_time': datetime.now().isoformat(),
                'config': {'quick_scan': True}
            }
            
            st.session_state.analysis_results = results
            st.session_state.scan_history.append(results)
            
            st.success("⚡ Quick analysis completed!")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Quick analysis failed: {str(e)}")

def display_enhanced_results(results, report_generator):
    """Display comprehensive analysis results with enhanced visualizations"""
    st.markdown("""
    <div class="results-header">
        <h2>📊 Comprehensive Analysis Results</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Threat assessment banner
    threat_assessment = results.get('threat_assessment', {})
    display_threat_banner(threat_assessment)
    
    # Create enhanced tabs
    tab_names = ["🔍 Overview", "🧬 Hashes", "📝 Strings", "📊 Entropy", "🎯 Patterns"]
    
    if 'virustotal' in results:
        tab_names.append("🌐 VirusTotal")
    if 'behavioral' in results:
        tab_names.append("🧠 Behavioral")
    
    tabs = st.tabs(tab_names)
    
    # Overview Tab
    with tabs[0]:
        display_overview_tab(results)
    
    # Hashes Tab
    with tabs[1]:
        if 'hashes' in results:
            display_hashes_tab(results['hashes'])
    
    # Strings Tab
    with tabs[2]:
        if 'strings' in results:
            display_strings_tab(results['strings'])
    
    # Entropy Tab
    with tabs[3]:
        if 'entropy' in results:
            display_entropy_tab(results['entropy'])
    
    # Patterns Tab
    with tabs[4]:
        if 'patterns' in results:
            display_patterns_tab(results['patterns'])
    
    # VirusTotal Tab
    tab_index = 5
    if 'virustotal' in results:
        with tabs[tab_index]:
            display_virustotal_tab(results['virustotal'])
        tab_index += 1
    
    # Behavioral Tab
    if 'behavioral' in results:
        with tabs[tab_index]:
            display_behavioral_tab(results['behavioral'])

def display_threat_banner(threat_assessment):
    """Display threat level banner with enhanced styling"""
    level = threat_assessment.get('level', 'Unknown')
    score = threat_assessment.get('score', 0)
    color = get_threat_color(level)
    
    st.markdown(f"""
    <div class="threat-banner" style="border-left: 5px solid {color};">
        <div class="threat-content">
            <div class="threat-level-large" style="color: {color};">
                {level.upper()} RISK
            </div>
            <div class="threat-score">
                Risk Score: {score}/100
            </div>
            <div class="threat-description">
                {get_threat_description(level)}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def display_overview_tab(results):
    """Display overview of all analysis results"""
    st.markdown("### 📋 Analysis Summary")
    
    col1, col2, col3 = st.columns(3)
    
    # File information
    with col1:
        file_info = results.get('file_info', {})
        st.markdown(f"""
        **📄 File Details:**
        - Name: `{file_info.get('name', 'Unknown')}`
        - Size: `{format_file_size(file_info.get('size', 0))}`
        - Analyzed: `{file_info.get('analysis_time', 'Unknown')[:19]}`
        """)
    
    # Analysis modules
    with col2:
        modules_completed = []
        if 'hashes' in results:
            modules_completed.append("✅ Hash Analysis")
        if 'strings' in results:
            modules_completed.append("✅ String Extraction")
        if 'entropy' in results:
            modules_completed.append("✅ Entropy Analysis")
        if 'patterns' in results:
            modules_completed.append("✅ Pattern Detection")
        if 'virustotal' in results:
            modules_completed.append("✅ VirusTotal Scan")
        if 'behavioral' in results:
            modules_completed.append("✅ Behavioral Analysis")
        
        st.markdown("**🔧 Completed Modules:**")
        for module in modules_completed:
            st.markdown(f"- {module}")
    
    # Key findings
    with col3:
        findings = []
        
        # Entropy finding
        if 'entropy' in results:
            entropy = results['entropy']
            if entropy > 7:
                findings.append("⚠️ High entropy detected")
            elif entropy > 6:
                findings.append("⚠️ Elevated entropy")
            else:
                findings.append("✅ Normal entropy")
        
        # VirusTotal finding
        if 'virustotal' in results:
            vt_data = results['virustotal']
            if 'stats' in vt_data:
                malicious = vt_data['stats']['malicious']
                if malicious > 0:
                    findings.append(f"⚠️ {malicious} engines flagged")
                else:
                    findings.append("✅ Clean by VirusTotal")
        
        # Pattern finding
        if 'patterns' in results:
            patterns = results['patterns']
            total_patterns = sum(len(v) for v in patterns.values())
            if total_patterns > 10:
                findings.append("⚠️ Many suspicious patterns")
            elif total_patterns > 0:
                findings.append("⚠️ Some patterns detected")
            else:
                findings.append("✅ No suspicious patterns")
        
        st.markdown("**🔍 Key Findings:**")
        for finding in findings:
            st.markdown(f"- {finding}")

def display_hashes_tab(hashes_data):
    """Display hash analysis results"""
    st.markdown("### 🧬 Cryptographic Hash Analysis")
    
    # Hash metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("MD5", "Calculated", delta="32 characters")
    with col2:
        st.metric("SHA1", "Calculated", delta="40 characters")
    with col3:
        st.metric("SHA256", "Calculated", delta="64 characters")
    
    # Hash table with copy functionality
    st.markdown("#### Hash Values")
    hash_df = pd.DataFrame([
        {"Algorithm": "MD5", "Hash Value": hashes_data['md5'], "Length": len(hashes_data['md5'])},
        {"Algorithm": "SHA1", "Hash Value": hashes_data['sha1'], "Length": len(hashes_data['sha1'])},
        {"Algorithm": "SHA256", "Hash Value": hashes_data['sha256'], "Length": len(hashes_data['sha256'])}
    ])
    
    st.dataframe(hash_df, use_container_width=True)
    
    # Hash lookup information
    st.markdown("#### 🔍 Hash Reputation")
    st.info("💡 These hashes can be used to check file reputation on threat intelligence platforms")

def display_strings_tab(strings_data):
    """Display string extraction results"""
    st.markdown(f"### 📝 String Analysis ({len(strings_data)} strings found)")
    
    if strings_data:
        # String statistics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Strings", len(strings_data))
        with col2:
            avg_length = sum(len(s) for s in strings_data) / len(strings_data)
            st.metric("Average Length", f"{avg_length:.1f}")
        with col3:
            max_length = max(len(s) for s in strings_data)
            st.metric("Max Length", max_length)
        with col4:
            min_length = min(len(s) for s in strings_data)
            st.metric("Min Length", min_length)
        
        # String categorization
        categorized_strings = categorize_strings(strings_data)
        
        # Display categories
        for category, strings in categorized_strings.items():
            if strings:
                with st.expander(f"{category} ({len(strings)} found)", expanded=False):
                    for string in strings[:20]:  # Limit display
                        st.code(string, language=None)
        
        # Full string table
        st.markdown("#### All Extracted Strings")
        strings_df = pd.DataFrame({
            "String": strings_data[:100],  # Limit for performance
            "Length": [len(s) for s in strings_data[:100]],
            "Category": [categorize_single_string(s) for s in strings_data[:100]]
        })
        st.dataframe(strings_df, use_container_width=True)
    else:
        st.info("No readable strings found in the file")

def display_entropy_tab(entropy_value):
    """Display entropy analysis with enhanced visualization"""
    st.markdown("### 📊 File Entropy Analysis")
    
    # Enhanced entropy gauge
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=entropy_value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "File Entropy Level", 'font': {'size': 24}},
        delta={'reference': 4, 'valueformat': '.2f'},
        gauge={
            'axis': {'range': [None, 8], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "#00ff88", 'thickness': 0.8},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 4], 'color': '#90EE90'},
                {'range': [4, 6], 'color': '#FFD700'},
                {'range': [6, 7], 'color': '#FFA500'},
                {'range': [7, 8], 'color': '#FF6347'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 7
            }
        }
    ))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={'color': "white"},
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Entropy interpretation
    st.markdown("#### 🧠 Entropy Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**📊 Entropy Score:**")
        st.markdown(f"**{entropy_value:.3f} / 8.000**")
        
        # Entropy category
        if entropy_value > 7.5:
            st.error("🚨 **VERY HIGH** - Likely encrypted/packed")
        elif entropy_value > 7:
            st.warning("⚠️ **HIGH** - May be compressed/encrypted")
        elif entropy_value > 6:
            st.warning("⚠️ **ELEVATED** - Contains compressed data")
        elif entropy_value > 4:
            st.success("✅ **NORMAL** - Typical entropy range")
        else:
            st.info("📊 **LOW** - Highly structured data")
    
    with col2:
        st.markdown("**🎯 Interpretation:**")
        interpretation = get_entropy_interpretation(entropy_value)
        st.markdown(interpretation)

def display_patterns_tab(patterns):
    """Display pattern detection results"""
    st.markdown("### 🎯 Suspicious Pattern Detection")
    
    # Pattern statistics
    total_patterns = sum(len(v) for v in patterns.values())
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Patterns", total_patterns)
    with col2:
        st.metric("URLs Found", len(patterns.get('urls', [])))
    with col3:
        st.metric("IP Addresses", len(patterns.get('ips', [])))
    with col4:
        st.metric("Email Addresses", len(patterns.get('emails', [])))
    
    # Display patterns by category
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 URLs", "🌍 IP Addresses", "📧 Emails", "🔍 Other Patterns"])
    
    with tab1:
        display_pattern_category("URLs", patterns.get('urls', []), "🌐")
    
    with tab2:
        display_pattern_category("IP Addresses", patterns.get('ips', []), "🌍")
    
    with tab3:
        display_pattern_category("Email Addresses", patterns.get('emails', []), "📧")
    
    with tab4:
        # Additional patterns
        other_patterns = patterns.get('registry_keys', []) + patterns.get('file_paths', [])
        display_pattern_category("Other Patterns", other_patterns, "🔍")

def display_virustotal_tab(vt_data):
    """Display VirusTotal scan results"""
    st.markdown("### 🌐 VirusTotal Analysis Results")
    
    if 'error' in vt_data:
        st.error(f"❌ VirusTotal Error: {vt_data['error']}")
        return
    
    # VirusTotal statistics
    if 'stats' in vt_data:
        stats = vt_data['stats']
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Engines", stats['total'])
        with col2:
            st.metric("Malicious", stats['malicious'], delta_color="inverse")
        with col3:
            st.metric("Suspicious", stats['suspicious'], delta_color="inverse")
        with col4:
            st.metric("Clean", stats['harmless'])
        
        # Detection ratio visualization
        fig = go.Figure(data=[
            go.Bar(
                x=['Malicious', 'Suspicious', 'Undetected', 'Harmless'],
                y=[stats['malicious'], stats['suspicious'], stats['undetected'], stats['harmless']],
                marker_color=['#ff4444', '#ffaa00', '#cccccc', '#00ff88']
            )
        ])
        
        fig.update_layout(
            title="VirusTotal Detection Results",
            xaxis_title="Detection Category",
            yaxis_title="Number of Engines",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={'color': "white"}
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Detailed engine results
    if 'engines' in vt_data:
        st.markdown("#### 🔍 Detailed Engine Results")
        
        engines_df = pd.DataFrame(vt_data['engines'])
        if not engines_df.empty:
            # Filter options
            filter_option = st.selectbox(
                "Filter results:",
                ["All", "Malicious Only", "Suspicious Only", "Clean Only"]
            )
            
            if filter_option == "Malicious Only":
                engines_df = engines_df[engines_df['result'] == 'malicious']
            elif filter_option == "Suspicious Only":
                engines_df = engines_df[engines_df['result'] == 'suspicious']
            elif filter_option == "Clean Only":
                engines_df = engines_df[engines_df['result'] == 'harmless']
            
            st.dataframe(engines_df, use_container_width=True)
        else:
            st.info("No detailed engine results available")
    
    # Additional VirusTotal information
    if 'scan_id' in vt_data:
        st.markdown(f"**🔗 Scan ID:** `{vt_data['scan_id']}`")
    
    if 'permalink' in vt_data:
        st.markdown(f"**🌐 VirusTotal Report:** [View Full Report]({vt_data['permalink']})")

def display_behavioral_tab(behavioral_data):
    """Display behavioral analysis results"""
    st.markdown("### 🧠 Behavioral Analysis")
    
    # Behavioral indicators
    indicators = behavioral_data.get('indicators', [])
    
    if indicators:
        st.markdown("#### ⚠️ Behavioral Indicators")
        
        for indicator in indicators:
            severity = indicator.get('severity', 'low')
            color = {'low': '#00ff88', 'medium': '#ffaa00', 'high': '#ff4444'}.get(severity, '#cccccc')
            
            st.markdown(f"""
            <div style="border-left: 4px solid {color}; padding: 10px; margin: 5px 0; background: rgba(255,255,255,0.1);">
                <strong>{indicator.get('title', 'Unknown')}</strong><br>
                <small>{indicator.get('description', 'No description')}</small>
            </div>
            """, unsafe_allow_html=True)
    
    # Capability assessment
    capabilities = behavioral_data.get('capabilities', [])
    if capabilities:
        st.markdown("#### 🎯 Detected Capabilities")
        
        cap_df = pd.DataFrame(capabilities)
        st.dataframe(cap_df, use_container_width=True)
    
    # Risk assessment
    risk_score = behavioral_data.get('risk_score', 0)
    st.markdown(f"#### 📊 Behavioral Risk Score: {risk_score}/100")
    
    # Risk gauge
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        title={'text': "Behavioral Risk"},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "#00ff88"},
            'steps': [
                {'range': [0, 30], 'color': "lightgreen"},
                {'range': [30, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "red"}
            ]
        }
    ))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={'color': "white"},
        height=300
    )
    
    st.plotly_chart(fig, use_container_width=True)

def display_pattern_category(title, patterns, icon):
    """Display patterns for a specific category"""
    if patterns:
        st.markdown(f"#### {icon} {title} ({len(patterns)} found)")
        
        for i, pattern in enumerate(patterns, 1):
            with st.expander(f"{icon} {title[:-1]} {i}", expanded=False):
                st.code(pattern, language=None)
                
                # Add context-specific information
                if title == "URLs":
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(pattern)
                        st.write(f"**Domain:** {parsed.netloc}")
                        st.write(f"**Path:** {parsed.path}")
                    except:
                        pass
                elif title == "IP Addresses":
                    # Could add geolocation or reputation lookup
                    st.write(f"**Type:** {'Private' if is_private_ip(pattern) else 'Public'}")
    else:
        st.info(f"No {title.lower()} detected in the file")

# Utility functions
def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def get_threat_color(threat_level):
    """Get color for threat level"""
    colors = {
        "Low": "#00ff88",
        "Medium": "#ffaa00", 
        "High": "#ff4444",
        "Critical": "#ff0000"
    }
    return colors.get(threat_level, "#888888")

def get_threat_description(threat_level):
    """Get description for threat level"""
    descriptions = {
        "Low": "File appears to be clean with minimal risk indicators",
        "Medium": "File contains some suspicious patterns that warrant attention",
        "High": "File shows significant malicious indicators and should be treated with caution",
        "Critical": "File is highly likely to be malicious and poses immediate threat"
    }
    return descriptions.get(threat_level, "Unknown threat level")

def categorize_strings(strings):
    """Categorize strings into different types"""
    categories = {
        "🌐 URLs & Domains": [],
        "📧 Email Addresses": [],
        "🗂️ File Paths": [],
        "🔑 Registry Keys": [],
        "🔤 ASCII Text": [],
        "🔢 Hexadecimal": [],
        "❓ Other": []
    }
    
    for string in strings:
        if re.match(r'https?://', string.lower()):
            categories["🌐 URLs & Domains"].append(string)
        elif re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', string):
            categories["📧 Email Addresses"].append(string)
        elif re.match(r'[A-Za-z]:\\', string) or string.startswith('/'):
            categories["🗂️ File Paths"].append(string)
        elif 'HKEY_' in string.upper():
            categories["🔑 Registry Keys"].append(string)
        elif re.match(r'^[0-9a-fA-F]+$', string) and len(string) > 8:
            categories["🔢 Hexadecimal"].append(string)
        elif string.isprintable() and not string.isdigit():
            categories["🔤 ASCII Text"].append(string)
        else:
            categories["❓ Other"].append(string)
    
    return categories

def categorize_single_string(string):
    """Categorize a single string"""
    if re.match(r'https?://', string.lower()):
        return "URL"
    elif re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', string):
        return "Email"
    elif re.match(r'[A-Za-z]:\\', string) or string.startswith('/'):
        return "File Path"
    elif 'HKEY_' in string.upper():
        return "Registry"
    elif re.match(r'^[0-9a-fA-F]+$', string) and len(string) > 8:
        return "Hexadecimal"
    elif string.isprintable() and not string.isdigit():
        return "ASCII"
    else:
        return "Other"

def get_entropy_interpretation(entropy_value):
    """Get detailed entropy interpretation"""
    if entropy_value > 7.5:
        return """
        **Very High Entropy (>7.5):**
        - File is likely encrypted, packed, or compressed
        - Common in malware that uses encryption to evade detection
        - Could indicate legitimate compressed archives
        - Requires further investigation
        """
    elif entropy_value > 7:
        return """
        **High Entropy (7.0-7.5):**
        - File may contain compressed or encrypted sections
        - Moderate suspicion level
        - Could be legitimate multimedia or archive files
        - Consider context and file type
        """
    elif entropy_value > 6:
        return """
        **Elevated Entropy (6.0-7.0):**
        - File contains some compressed or binary data
        - Normal for many file types
        - Low suspicion level
        - Generally acceptable range
        """
    elif entropy_value > 4:
        return """
        **Normal Entropy (4.0-6.0):**
        - Typical entropy range for most files
        - Good balance of structured and random data
        - No entropy-based concerns
        - File appears normal
        """
    else:
        return """
        **Low Entropy (<4.0):**
        - Highly structured or repetitive data
        - Common in text files or simple executables
        - No security concerns from entropy perspective
        - File contains predictable patterns
        """

def is_private_ip(ip):
    """Check if IP address is in private range"""
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except:
        return False

if __name__ == "__main__":
    main()
