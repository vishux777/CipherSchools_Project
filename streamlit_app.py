# This is the main entry point for Streamlit Cloud deployment
# It imports and runs the working app
import streamlit as st
import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the working app
from working_app import main

if __name__ == "__main__":
    main()