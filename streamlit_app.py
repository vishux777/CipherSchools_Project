import streamlit as st
import sys
import os

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import and run the main app
try:
    from app import main
    main()
except ImportError as e:
    st.error(f"Import error: {e}")
    st.info("Running basic version...")
    
    st.title("🛡️ MalwareShield Pro")
    st.write("Advanced Threat Detection System")
    st.write("Created by vishux777")
    
    uploaded_file = st.file_uploader("Upload file for analysis")
    if uploaded_file:
        st.success("File uploaded successfully!")
        st.write(f"File: {uploaded_file.name}")
        st.write(f"Size: {len(uploaded_file.getvalue())} bytes")
