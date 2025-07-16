"""
MalwareShield Pro - Enhanced Mobile-Compatible Malware Detection Tool

A comprehensive Streamlit-based malware detection application with VirusTotal integration,
entropy analysis, pattern detection, mobile responsiveness, and professional reporting capabilities.
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

# Configure page with mobile-friendly settings
st.set_page_config(
    page_title="🛡️ MalwareShield Pro - Advanced Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced mobile-responsive CSS styling
st.markdown("""
<style>
/* Mobile-First Responsive Design */
.main {
    background: linear-gradient(135deg, #0e1117 0%, #1a1d29 100%);
    color: #fafafa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    padding: 10px;
}

.stApp {
    background: linear-gradient(135deg, #0e1117 0%, #1a1d29 100%);
}

/* Mobile-responsive sidebar */
.css-1d391kg, .css-1544g2n {
    background: linear-gradient(180deg, #262730 0%, #1e1f26 100%);
    border-right: 2px solid #00aaff20;
}

@media (max-width: 768px) {
    .css-1d391kg, .css-1544g2n {
        width: 100% !important;
        min-width: 100% !important;
    }
    
    .main .block-container {
        padding-left: 1rem !important;
        padding-right: 1rem !important;
        padding-top: 1rem !important;
        max-width: 100% !important;
    }
    
    .stButton > button {
        width: 100% !important;
        min-height: 48px !important;
        font-size: 16px !important;
        padding: 12px 20px !important;
    }
    
    .stMetric {
        padding: 10px !important;
        margin: 5px 0 !important;
    }
    
    .stMetric > div {
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
    }
    
    .stMetric label {
        font-size: 14px !important;
    }
    
    .stMetric [data-testid="metric-value"] {
        font-size: 16px !important;
        word-break: break-all !important;
    }
    
    /* Hash display styling for mobile */
    .stCodeBlock {
        font-size: 12px !important;
        word-break: break-all !important;
        white-space: pre-wrap !important;
        overflow-wrap: break-word !important;
    }
    
    .stCodeBlock code {
        white-space: pre-wrap !important;
        word-break: break-all !important;
    }
}

/* Enhanced mobile-friendly file uploader */
.stFileUploader {
    background: linear-gradient(135deg, #262730, #1a1d29);
    border: 2px dashed #00aaff;
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    transition: all 0.3s ease;
    min-height: 120px;
    display: flex;
    align-items: center;
    justify-content: center;
}

@media (max-width: 768px) {
    .stFileUploader {
        padding: 15px;
        min-height: 100px;
        border-radius: 10px;
    }
}

.stFileUploader:hover {
    border-color: #0088cc;
    box-shadow: 0 0 20px rgba(0, 170, 255, 0.2);
    transform: translateY(-2px);
}

@media (max-width: 480px) {
    .stFileUploader:hover {
        transform: none;
    }
}

/* Mobile-optimized card styling */
.scan-card {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 20px;
    border-radius: 15px;
    border: 1px solid #444;
    margin: 15px 0;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(10px);
    transition: all 0.3s ease;
}

@media (max-width: 768px) {
    .scan-card {
        padding: 15px;
        margin: 10px 0;
        border-radius: 10px;
    }
}

.scan-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 40px rgba(0, 170, 255, 0.1);
    border-color: #00aaff;
}

@media (max-width: 480px) {
    .scan-card:hover {
        transform: translateY(-2px);
    }
}

/* Responsive header */
.main-header {
    background: linear-gradient(135deg, rgba(26, 29, 41, 0.9), rgba(14, 17, 23, 0.9));
    backdrop-filter: blur(20px);
    padding: 30px 20px;
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    margin-bottom: 30px;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    position: relative;
    overflow: hidden;
}

@media (max-width: 768px) {
    .main-header {
        padding: 20px 15px;
        margin-bottom: 20px;
        border-radius: 15px;
    }
}

.main-header h1 {
    font-size: 2.5em;
    margin: 0;
    background: linear-gradient(135deg, #00aaff, #0088cc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-weight: bold;
}

@media (max-width: 768px) {
    .main-header h1 {
        font-size: 2em;
    }
}

@media (max-width: 480px) {
    .main-header h1 {
        font-size: 1.5em;
    }
}

.main-header h3 {
    color: #cccccc;
    font-weight: 300;
    margin: 10px 0;
    font-size: 1.2em;
}

@media (max-width: 768px) {
    .main-header h3 {
        font-size: 1em;
    }
}

/* Enhanced mobile-responsive threat level banners */
.threat-critical, .threat-high, .threat-medium, .threat-low, .threat-clean {
    padding: 20px;
    border-radius: 15px;
    color: white;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    font-size: 1.1em;
    word-wrap: break-word;
}

@media (max-width: 768px) {
    .threat-critical, .threat-high, .threat-medium, .threat-low, .threat-clean {
        padding: 15px;
        margin: 15px 0;
        border-radius: 10px;
        font-size: 1em;
    }
}

.threat-critical {
    background: linear-gradient(135deg, #8B0000, #DC143C);
    box-shadow: 0 8px 32px rgba(220, 20, 60, 0.4);
    border: 2px solid #FF1744;
    animation: pulse-critical 2s infinite;
}

.threat-high {
    background: linear-gradient(135deg, #FF4500, #FF6347);
    box-shadow: 0 8px 32px rgba(255, 99, 71, 0.4);
    border: 2px solid #FF5722;
    animation: pulse-high 2.5s infinite;
}

.threat-medium {
    background: linear-gradient(135deg, #FF8C00, #FFA500);
    box-shadow: 0 8px 32px rgba(255, 165, 0, 0.4);
    border: 2px solid #FF9800;
}

.threat-low {
    background: linear-gradient(135deg, #228B22, #32CD32);
    box-shadow: 0 8px 32px rgba(50, 205, 50, 0.4);
    border: 2px solid #4CAF50;
}

.threat-clean {
    background: linear-gradient(135deg, #228B22, #32CD32);
    box-shadow: 0 8px 32px rgba(50, 205, 50, 0.4);
    border: 2px solid #4CAF50;
    animation: pulse-clean 3s infinite;
}

@keyframes pulse-critical {
    0%, 100% { transform: scale(1); box-shadow: 0 8px 32px rgba(220, 20, 60, 0.4); }
    50% { transform: scale(1.02); box-shadow: 0 12px 40px rgba(220, 20, 60, 0.6); }
}

@keyframes pulse-high {
    0%, 100% { box-shadow: 0 8px 32px rgba(255, 99, 71, 0.4); }
    50% { box-shadow: 0 12px 40px rgba(255, 99, 71, 0.6); }
}

@keyframes pulse-clean {
    0%, 100% { box-shadow: 0 8px 32px rgba(50, 205, 50, 0.4); }
    50% { box-shadow: 0 12px 40px rgba(50, 205, 50, 0.6); }
}

/* Mobile-optimized metric cards */
.metric-card {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 15px;
    border-radius: 12px;
    border: 1px solid #444;
    margin: 10px 0;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
}

@media (max-width: 768px) {
    .metric-card {
        padding: 12px;
        margin: 8px 0;
        border-radius: 8px;
    }
}

.metric-card h4 {
    color: #00aaff;
    margin: 0 0 10px 0;
    font-size: 1.1em;
}

@media (max-width: 768px) {
    .metric-card h4 {
        font-size: 1em;
    }
}

/* Touch-friendly buttons */
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
    min-height: 44px;
    cursor: pointer;
}

@media (max-width: 768px) {
    .stButton > button {
        padding: 15px 20px;
        font-size: 14px;
        min-height: 48px;
        width: 100%;
    }
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(0, 170, 255, 0.4);
}

@media (max-width: 480px) {
    .stButton > button:hover {
        transform: none;
    }
}

/* Professional Credits Section */
.credits-section {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 30px;
    border-radius: 20px;
    border: 1px solid #444;
    margin: 30px 0;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
}

@media (max-width: 768px) {
    .credits-section {
        padding: 20px;
        margin: 20px 0;
        border-radius: 15px;
    }
}

.credits-title {
    text-align: center;
    color: #00aaff;
    font-size: 2.5em;
    font-weight: bold;
    margin-bottom: 30px;
    background: linear-gradient(135deg, #00aaff, #0088cc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

@media (max-width: 768px) {
    .credits-title {
        font-size: 2em;
        margin-bottom: 20px;
    }
}

.credits-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 25px;
    margin-bottom: 30px;
}

@media (max-width: 768px) {
    .credits-grid {
        grid-template-columns: 1fr;
        gap: 20px;
        margin-bottom: 20px;
    }
}

.credit-card {
    background: linear-gradient(135deg, #1a1d29, #0f1419);
    padding: 25px;
    border-radius: 15px;
    border: 1px solid #333;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

@media (max-width: 768px) {
    .credit-card {
        padding: 20px;
        border-radius: 12px;
    }
}

.credit-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 40px rgba(0, 170, 255, 0.2);
    border-color: #00aaff;
}

@media (max-width: 480px) {
    .credit-card:hover {
        transform: translateY(-2px);
    }
}

.credit-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(135deg, #00aaff, #0088cc);
}

.credit-header {
    display: flex;
    align-items: center;
    margin-bottom: 15px;
}

.credit-icon {
    font-size: 2.5em;
    margin-right: 15px;
}

@media (max-width: 768px) {
    .credit-icon {
        font-size: 2em;
        margin-right: 10px;
    }
}

.credit-info h3 {
    color: #00aaff;
    margin: 0;
    font-size: 1.3em;
}

.credit-info p {
    color: #cccccc;
    margin: 5px 0;
    font-size: 0.9em;
}

@media (max-width: 768px) {
    .credit-info h3 {
        font-size: 1.2em;
    }
}

.credit-description {
    color: #aaaaaa;
    line-height: 1.6;
    margin-bottom: 15px;
}

.credit-links {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.credit-link {
    background: linear-gradient(135deg, #00aaff, #0088cc);
    color: white;
    padding: 8px 16px;
    border-radius: 8px;
    text-decoration: none;
    font-size: 0.9em;
    transition: all 0.3s ease;
    display: inline-block;
}

@media (max-width: 768px) {
    .credit-link {
        padding: 10px 16px;
        font-size: 0.8em;
    }
}

.credit-link:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 170, 255, 0.3);
}

/* Mobile-responsive columns */
@media (max-width: 768px) {
    .stColumns {
        flex-direction: column;
    }
    
    .stColumn {
        width: 100% !important;
        margin-bottom: 20px;
    }
}

/* Mobile-friendly text sizes */
@media (max-width: 768px) {
    .stMarkdown h1 {
        font-size: 1.8em;
    }
    
    .stMarkdown h2 {
        font-size: 1.5em;
    }
    
    .stMarkdown h3 {
        font-size: 1.3em;
    }
    
    .stMarkdown p {
        font-size: 0.9em;
    }
}

/* Responsive tables */
@media (max-width: 768px) {
    .stDataFrame {
        font-size: 0.8em;
    }
    
    .stDataFrame table {
        min-width: 100%;
    }
}

/* Mobile-optimized progress bars */
@media (max-width: 768px) {
    .stProgress {
        height: 8px;
    }
}

/* Touch-friendly metrics */
.stMetric {
    background: linear-gradient(135deg, #262730, #1a1d29);
    padding: 15px;
    border-radius: 10px;
    border: 1px solid #444;
    margin: 10px 0;
}

@media (max-width: 768px) {
    .stMetric {
        padding: 12px;
        margin: 8px 0;
    }
}

/* Responsive spacing */
@media (max-width: 768px) {
    .main .block-container {
        padding: 1rem;
    }
}

/* Mobile-optimized alerts */
.stAlert {
    background-color: #262730;
    border: 1px solid #444;
    color: #fafafa;
    border-radius: 10px;
    padding: 15px;
    margin: 10px 0;
}

@media (max-width: 768px) {
    .stAlert {
        padding: 12px;
        margin: 8px 0;
        border-radius: 8px;
    }
}

/* Responsive sidebar content */
@media (max-width: 768px) {
    .sidebar .sidebar-content {
        padding: 1rem;
    }
}

/* Enhanced mobile scrolling */
@media (max-width: 768px) {
    .main {
        overflow-x: hidden;
    }
    
    .stDataFrame {
        overflow-x: auto;
    }
}
</style>
""", unsafe_allow_html=True)

def create_professional_header():
    """Create a professional header with mobile-responsive design"""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ MalwareShield Pro</h1>
        <h3>Advanced Threat Detection & Analysis Platform</h3>
        <p style="color: #999; margin-top: 10px; font-size: 0.9em;">
            Comprehensive malware detection with VirusTotal integration, entropy analysis, and professional reporting
        </p>
    </div>
    """, unsafe_allow_html=True)

def create_credits_section():
    """Create an enhanced professional credits section with card-based layout"""
    st.markdown("## 🎯 Development Team & Credits")
    
    # Developer card
    with st.container():
        st.markdown("""
        <div style="background: linear-gradient(135deg, #262730, #1a1d29); padding: 20px; border-radius: 15px; 
                    border: 1px solid #444; margin: 15px 0; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="font-size: 2em; margin-right: 15px;">👨‍💻</div>
                <div>
                    <h3 style="color: #00aaff; margin: 0;">Lead Developer</h3>
                    <p style="color: #cccccc; margin: 0;">vishux777</p>
                </div>
            </div>
            <p style="color: #aaaaaa; line-height: 1.6; margin-bottom: 15px;">
                Principal architect and developer of MalwareShield Pro. Responsible for core functionality, 
                threat detection algorithms, and system architecture.
            </p>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <a href="https://github.com/vishux777" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
                   color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
                   GitHub Profile
                </a>
                <a href="https://github.com/vishux777/CipherSchools_Project" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
                   color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
                   Project Repo
                </a>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Technology stack in columns
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #262730, #1a1d29); padding: 20px; border-radius: 15px; 
                    border: 1px solid #444; margin: 15px 0; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="font-size: 2em; margin-right: 15px;">🏫</div>
                <div>
                    <h3 style="color: #00aaff; margin: 0;">Educational Partner</h3>
                    <p style="color: #cccccc; margin: 0;">CipherSchools</p>
                </div>
            </div>
            <p style="color: #aaaaaa; line-height: 1.6; margin-bottom: 15px;">
                Educational platform providing cybersecurity training and resources. This project was developed 
                as part of advanced cybersecurity coursework.
            </p>
            <a href="https://cipherschools.com" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
               color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
               Visit CipherSchools
            </a>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div style="background: linear-gradient(135deg, #262730, #1a1d29); padding: 20px; border-radius: 15px; 
                    border: 1px solid #444; margin: 15px 0; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="font-size: 2em; margin-right: 15px;">⚡</div>
                <div>
                    <h3 style="color: #00aaff; margin: 0;">Technology Stack</h3>
                    <p style="color: #cccccc; margin: 0;">Streamlit & Python</p>
                </div>
            </div>
            <p style="color: #aaaaaa; line-height: 1.6; margin-bottom: 15px;">
                Built with Streamlit for the web interface, Python for backend processing, and various 
                specialized libraries for file analysis and threat detection.
            </p>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <a href="https://streamlit.io" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
                   color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
                   Streamlit
                </a>
                <a href="https://python.org" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
                   color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
                   Python
                </a>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #262730, #1a1d29); padding: 20px; border-radius: 15px; 
                    border: 1px solid #444; margin: 15px 0; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="font-size: 2em; margin-right: 15px;">🔍</div>
                <div>
                    <h3 style="color: #00aaff; margin: 0;">VirusTotal Integration</h3>
                    <p style="color: #cccccc; margin: 0;">Threat Intelligence API</p>
                </div>
            </div>
            <p style="color: #aaaaaa; line-height: 1.6; margin-bottom: 15px;">
                External threat intelligence powered by VirusTotal's comprehensive malware detection database 
                and analysis engines from multiple security vendors.
            </p>
            <a href="https://virustotal.com" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
               color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
               VirusTotal
            </a>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div style="background: linear-gradient(135deg, #262730, #1a1d29); padding: 20px; border-radius: 15px; 
                    border: 1px solid #444; margin: 15px 0; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="font-size: 2em; margin-right: 15px;">📊</div>
                <div>
                    <h3 style="color: #00aaff; margin: 0;">Visualization & Analytics</h3>
                    <p style="color: #cccccc; margin: 0;">Plotly & Pandas</p>
                </div>
            </div>
            <p style="color: #aaaaaa; line-height: 1.6; margin-bottom: 15px;">
                Interactive charts and data analysis powered by Plotly for visualization and Pandas 
                for data manipulation and statistical analysis.
            </p>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <a href="https://plotly.com" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
                   color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
                   Plotly
                </a>
                <a href="https://pandas.pydata.org" style="background: linear-gradient(135deg, #00aaff, #0088cc); 
                   color: white; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;">
                   Pandas
                </a>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Project information footer
    st.markdown("""
    <div style="text-align: center; margin-top: 30px; padding: 20px; 
                background: linear-gradient(135deg, #1a1d29, #0f1419); border-radius: 15px;">
        <h3 style="color: #00aaff; margin-bottom: 15px;">🚀 Project Information</h3>
        <p style="color: #cccccc; line-height: 1.6; margin-bottom: 15px;">
            MalwareShield Pro is an advanced cybersecurity tool designed for threat detection and analysis. 
            It combines local file analysis with external threat intelligence to provide comprehensive malware detection capabilities.
        </p>
        <p style="color: #999; font-size: 0.9em;">
            Version 2.0 | Enhanced Mobile Edition | © 2025 MalwareShield Pro
        </p>
    </div>
    """, unsafe_allow_html=True)

def initialize_session_state():
    """Initialize session state variables"""
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'uploaded_file' not in st.session_state:
        st.session_state.uploaded_file = None
    if 'scan_complete' not in st.session_state:
        st.session_state.scan_complete = False

def create_analysis_config():
    """Create analysis configuration from sidebar settings"""
    st.sidebar.header("🔧 Analysis Configuration")
    
    config = {
        'deep_scan': st.sidebar.checkbox("Deep Scan Mode", value=True, help="Perform comprehensive analysis"),
        'entropy_analysis': st.sidebar.checkbox("Entropy Analysis", value=True, help="Calculate file entropy"),
        'string_extraction': st.sidebar.checkbox("String Extraction", value=True, help="Extract readable strings"),
        'pattern_matching': st.sidebar.checkbox("Pattern Matching", value=True, help="Detect malware patterns"),
        'virustotal_scan': st.sidebar.checkbox("VirusTotal Scan", value=True, help="External threat intelligence"),
        'generate_report': st.sidebar.checkbox("Generate PDF Report", value=True, help="Create detailed report")
    }
    
    # Analysis thresholds
    st.sidebar.subheader("🎯 Detection Thresholds")
    config['entropy_threshold'] = st.sidebar.slider("Entropy Threshold", 0.0, 8.0, 6.5, 0.1)
    config['string_threshold'] = st.sidebar.slider("String Count Threshold", 10, 1000, 100, 10)
    
    return config

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def display_threat_level_banner(threat_level, score):
    """Display threat level with appropriate styling"""
    level_config = {
        'CRITICAL': ('🚨 CRITICAL THREAT DETECTED', 'threat-critical'),
        'HIGH': ('⚠️ HIGH THREAT LEVEL', 'threat-high'),
        'MEDIUM': ('🟡 MEDIUM THREAT LEVEL', 'threat-medium'),
        'LOW': ('🟢 LOW THREAT LEVEL', 'threat-low'),
        'CLEAN': ('✅ FILE APPEARS CLEAN', 'threat-clean'),
        'UNKNOWN': ('❓ UNKNOWN THREAT LEVEL', 'threat-medium')
    }
    
    message, css_class = level_config.get(threat_level, ('❓ UNKNOWN THREAT LEVEL', 'threat-medium'))
    
    st.markdown(f"""
    <div class="{css_class}">
        <h2 style="margin: 0; font-size: 1.5em;">{message}</h2>
        <p style="margin: 10px 0 0 0; font-size: 1.2em;">Threat Score: {score}/100</p>
    </div>
    """, unsafe_allow_html=True)

def create_analysis_dashboard(results):
    """Create comprehensive analysis dashboard with mobile-responsive design"""
    if not results:
        st.error("No analysis results available")
        return
    
    # Threat assessment banner
    threat_info = results.get('threat_assessment', {})
    threat_level = threat_info.get('level', 'UNKNOWN')
    threat_score = threat_info.get('score', 0)
    
    display_threat_level_banner(threat_level, threat_score)
    
    # File information card
    st.markdown('<div class="scan-card">', unsafe_allow_html=True)
    st.subheader("📄 File Information")
    
    file_info = results.get('file_info', {})
    
    # Use responsive columns for mobile
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.metric("File Name", file_info.get('filename', 'Unknown'))
        st.metric("File Size", format_file_size(file_info.get('size', 0)))
        st.metric("File Type", file_info.get('type', 'Unknown'))
    
    with col2:
        # Display full hashes with copy-friendly formatting
        md5_hash = file_info.get('md5', 'N/A')
        sha1_hash = file_info.get('sha1', 'N/A')
        sha256_hash = file_info.get('sha256', 'N/A')
        
        st.markdown("**MD5 Hash:**")
        st.code(md5_hash, language=None)
        
        st.markdown("**SHA1 Hash:**")
        st.code(sha1_hash, language=None)
        
        st.markdown("**SHA256 Hash:**")
        st.code(sha256_hash, language=None)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Analysis results
    analysis = results.get('analysis', {})
    if analysis:
        st.markdown('<div class="scan-card">', unsafe_allow_html=True)
        st.subheader("🔍 Analysis Results")
        
        # Responsive metrics layout
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Entropy", f"{analysis.get('entropy', 0):.2f}")
        
        with col2:
            st.metric("Strings Found", len(analysis.get('strings', [])))
        
        with col3:
            st.metric("Patterns Detected", len(analysis.get('patterns', {})))
        
        # Entropy visualization
        if 'entropy' in analysis:
            entropy_val = analysis['entropy']
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=entropy_val,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "File Entropy"},
                delta={'reference': 6.5},
                gauge={'axis': {'range': [None, 8]},
                      'bar': {'color': "darkblue"},
                      'steps': [
                          {'range': [0, 4], 'color': "lightgreen"},
                          {'range': [4, 6.5], 'color': "yellow"},
                          {'range': [6.5, 8], 'color': "red"}],
                      'threshold': {'line': {'color': "red", 'width': 4},
                                   'thickness': 0.75, 'value': 6.5}}))
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # VirusTotal results
    vt_results = results.get('virustotal', {})
    if vt_results and 'stats' in vt_results:
        st.markdown('<div class="scan-card">', unsafe_allow_html=True)
        st.subheader("🔍 VirusTotal Results")
        
        stats = vt_results['stats']
        
        # Responsive metrics for mobile
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Malicious", stats.get('malicious', 0))
        
        with col2:
            st.metric("Suspicious", stats.get('suspicious', 0))
        
        with col3:
            st.metric("Clean", stats.get('harmless', 0))
        
        with col4:
            st.metric("Total Engines", stats.get('total', 0))
        
        # Detection ratio visualization
        if stats.get('total', 0) > 0:
            detection_data = {
                'Status': ['Malicious', 'Suspicious', 'Clean', 'Undetected'],
                'Count': [
                    stats.get('malicious', 0),
                    stats.get('suspicious', 0),
                    stats.get('harmless', 0),
                    stats.get('undetected', 0)
                ],
                'Color': ['red', 'orange', 'green', 'gray']
            }
            
            fig = px.pie(
                values=detection_data['Count'],
                names=detection_data['Status'],
                title="Detection Results Distribution",
                color_discrete_map={
                    'Malicious': 'red',
                    'Suspicious': 'orange',
                    'Clean': 'green',
                    'Undetected': 'gray'
                }
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Threat assessment details
    if threat_info:
        st.markdown('<div class="scan-card">', unsafe_allow_html=True)
        st.subheader("⚡ Threat Assessment")
        
        reasons = threat_info.get('reasons', [])
        if reasons:
            st.write("**Assessment Factors:**")
            for reason in reasons:
                st.write(f"• {reason}")
        
        # Threat score visualization
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=threat_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Threat Score"},
            gauge={'axis': {'range': [None, 100]},
                  'bar': {'color': "darkred"},
                  'steps': [
                      {'range': [0, 25], 'color': "lightgreen"},
                      {'range': [25, 50], 'color': "yellow"},
                      {'range': [50, 75], 'color': "orange"},
                      {'range': [75, 100], 'color': "red"}],
                  'threshold': {'line': {'color': "red", 'width': 4},
                               'thickness': 0.75, 'value': 75}}))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

def perform_analysis(uploaded_file, config):
    """Perform comprehensive malware analysis"""
    if not uploaded_file:
        return None
    
    try:
        # Initialize components
        analysis_engine = AnalysisEngine()
        threat_scorer = ThreatScorer()
        vt_api = VirusTotalAPI(os.getenv("VIRUSTOTAL_API_KEY", ""))
        
        # Read file data
        file_data = uploaded_file.read()
        filename = uploaded_file.name
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Step 1: File analysis
        status_text.text("🔍 Analyzing file structure...")
        progress_bar.progress(20)
        
        analysis_results = analysis_engine.analyze_file(file_data, filename, config)
        
        # Step 2: Threat scoring
        status_text.text("⚡ Calculating threat score...")
        progress_bar.progress(40)
        
        threat_assessment = threat_scorer.calculate_score(analysis_results)
        
        # Step 3: VirusTotal scan (if enabled and configured)
        virustotal_results = {}
        if config.get('virustotal_scan', False) and vt_api.is_configured():
            status_text.text("🌐 Checking VirusTotal database(will take around 1 min)...")
            progress_bar.progress(60)
            
            vt_results = vt_api.scan_file(file_data, filename)
            if 'error' not in vt_results:
                virustotal_results = vt_results
        
        # Step 4: Compile results
        status_text.text("📊 Compiling results...")
        progress_bar.progress(80)
        
        # File information with optimized hash calculation
        # Calculate all hashes in a single pass for better performance
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        # Process data in chunks for large files
        chunk_size = 8192
        data_io = io.BytesIO(file_data)
        
        while True:
            chunk = data_io.read(chunk_size)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
        
        file_info = {
            'filename': filename,
            'size': len(file_data),
            'type': analysis_results.get('file_type', 'Unknown'),
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
        
        # Compile final results
        results = {
            'file_info': file_info,
            'analysis': analysis_results,
            'threat_assessment': threat_assessment,
            'virustotal': virustotal_results,
            'timestamp': datetime.now().isoformat(),
            'config': config
        }
        
        status_text.text("✅ Analysis complete!")
        progress_bar.progress(100)
        
        # Clear progress indicators
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        return results
        
    except Exception as e:
        st.error(f"Analysis failed: {str(e)}")
        return None

def create_download_buttons(results):
    """Create download buttons for reports with improved PDF generation"""
    if not results:
        return
    
    st.markdown('<div class="scan-card">', unsafe_allow_html=True)
    st.subheader("📥 Download Reports")
    
    # Create columns for download buttons
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON Report
        json_report = ReportGenerator().export_json(results)
        st.download_button(
            label="📄 Download JSON Report",
            data=json_report,
            file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        # PDF Report with enhanced error handling
        try:
            report_generator = ReportGenerator()
            pdf_data = report_generator.generate_report(results)
            
            if pdf_data and not isinstance(pdf_data, str):
                st.download_button(
                    label="📑 Download PDF Report",
                    data=pdf_data,
                    file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                # Fallback to text report
                text_report = report_generator._generate_text_report(results)
                st.download_button(
                    label="📝 Download Text Report",
                    data=text_report,
                    file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
                st.info("📋 PDF generation unavailable - text report provided instead")
        except Exception as e:
            st.error(f"Report generation failed: {str(e)}")
            st.info("💡 Try installing ReportLab: pip install reportlab")
    
    st.markdown('</div>', unsafe_allow_html=True)

def main():
    """Main application function"""
    # Initialize session state
    initialize_session_state()
    
    # Create professional header
    create_professional_header()
    
    # Create sidebar configuration
    config = create_analysis_config()
    
    # API status in sidebar
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔗 API Status")
    
    vt_api = VirusTotalAPI(os.getenv("VIRUSTOTAL_API_KEY", ""))
    if vt_api.is_configured():
        st.sidebar.success("✅ VirusTotal API: Connected")
    else:
        st.sidebar.warning("⚠️ VirusTotal API: Not configured")
        st.sidebar.info("💡 Add VIRUSTOTAL_API_KEY environment variable for enhanced detection")
    
    # Main content area
    st.header("🔍 File Analysis")
    
    # File upload with mobile-friendly interface
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=['exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'rar', 'bat', 'cmd', 'scr', 'vbs', 'js', 'jar'],
        help="Upload suspicious files for comprehensive malware analysis",
        key="file_uploader"
    )
    
    if uploaded_file:
        # Display file information
        st.info(f"📁 Selected file: {uploaded_file.name} ({format_file_size(uploaded_file.size)})")
        
        # Analysis button
        if st.button("🚀 Start Analysis", use_container_width=True):
            st.session_state.uploaded_file = uploaded_file
            st.session_state.scan_complete = False
            
            # Perform analysis
            with st.spinner("Analyzing file..."):
                results = perform_analysis(uploaded_file, config)
                
                if results:
                    st.session_state.analysis_results = results
                    st.session_state.scan_complete = True
                    show_result_animation(results.get('threat_assessment', {}).get('level', 'UNKNOWN'))
                else:
                    st.error("Analysis failed. Please try again.")
    
    # Display results if available
    if st.session_state.analysis_results and st.session_state.scan_complete:
        st.markdown("---")
        st.header("📊 Analysis Results")
        
        # Create analysis dashboard
        create_analysis_dashboard(st.session_state.analysis_results)
        
        # Download buttons
        create_download_buttons(st.session_state.analysis_results)
    
    # About section
    st.markdown("---")
    st.header("ℹ️ About MalwareShield Pro")
    
    about_col1, about_col2 = st.columns(2)
    
    with about_col1:
        st.markdown("""
        **Features:**
        - 🔍 Comprehensive file analysis
        - 🧠 Advanced entropy calculation
        - 🔗 VirusTotal integration
        - 📊 Interactive visualizations
        - 📑 Professional PDF reports
        - 📱 Mobile-responsive design
        """)
    
    with about_col2:
        st.markdown("""
        **Supported File Types:**
        - Executable files (.exe, .dll, .scr)
        - Documents (.pdf, .doc, .docx)
        - Archives (.zip, .rar)
        - Scripts (.bat, .cmd, .vbs, .js)
        - Java files (.jar)
        """)
    
    # Enhanced credits section
    st.markdown("---")
    create_credits_section()

if __name__ == "__main__":
    main()
