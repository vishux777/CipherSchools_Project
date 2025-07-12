"""
MalwareShield Pro - Main Application Entry Point

This is the main entry point for the Streamlit application.
It handles imports and fallback mechanisms for robust operation.
"""

import streamlit as st
import sys
import os
import traceback

# Add the current directory to the Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def main():
    """Main application entry point with error handling"""
    try:
        # Try to import and run the main application
        from app import main as app_main
        app_main()
        
    except ImportError as e:
        st.error(f"❌ Import Error: {str(e)}")
        st.error("📋 Error Details:")
        st.code(traceback.format_exc())
        
        # Fallback basic application
        st.title("🛡️ MalwareShield Pro")
        st.error("⚠️ Some modules failed to load. Running in basic mode.")
        
        st.markdown("""
        ### 🔧 Troubleshooting Steps:
        1. **Check Dependencies**: Ensure all required packages are installed
        2. **Verify File Structure**: Make sure all utility modules are present
        3. **Check Python Path**: Verify the application can find all modules
        
        ### 📁 Expected File Structure:
        ```
        ├── streamlit_app.py (this file)
        ├── app.py
        └── utils/
            ├── __init__.py
            ├── virustotal.py
            ├── analysis_engine.py
            ├── report_generator.py
            └── threat_scorer.py
        ```
        """)
        
        # Basic file uploader for debugging
        uploaded_file = st.file_uploader(
            "Upload file for basic analysis", 
            help="Basic file information will be displayed"
        )
        
        if uploaded_file:
            st.success("✅ File uploaded successfully!")
            st.write(f"**📝 Filename:** {uploaded_file.name}")
            st.write(f"**📏 Size:** {len(uploaded_file.getvalue())} bytes")
            st.write(f"**🏷️ Type:** {uploaded_file.type or 'Unknown'}")
            
            # Basic hash calculation
            try:
                import hashlib
                file_data = uploaded_file.getvalue()
                md5_hash = hashlib.md5(file_data).hexdigest()
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                
                st.write("**🔍 File Hashes:**")
                st.code(f"MD5: {md5_hash}")
                st.code(f"SHA256: {sha256_hash}")
                
            except Exception as hash_error:
                st.error(f"Could not calculate hashes: {hash_error}")
    
    except Exception as e:
        st.error(f"❌ Application Error: {str(e)}")
        st.error("📋 Full Error Details:")
        st.code(traceback.format_exc())
        
        st.markdown("""
        ### 🆘 Critical Error
        The application encountered a critical error and cannot continue.
        Please check the error details above and contact support if needed.
        """)

if __name__ == "__main__":
    main()

