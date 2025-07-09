# 🛡️ MalwareShield

A professional malware analysis platform built with Streamlit for static file analysis.

## Features

- **File Upload & Analysis**: Drag-and-drop file upload with comprehensive analysis
- **Hash Calculation**: MD5, SHA1, and SHA256 hash generation
- **Entropy Analysis**: File entropy calculation with visual gauge
- **String Extraction**: Extract and analyze readable strings from files
- **Pattern Detection**: Identify URLs, IP addresses, and email addresses
- **Threat Assessment**: Automated threat level calculation
- **Cybersecurity-themed UI**: Professional dark theme with modern design

## Live Demo

Visit the application at: [https://darkexpo.streamlit.app/]

## Deployment

### Streamlit Cloud (Recommended)

1. Fork/clone this repository
2. Go to [share.streamlit.io](https://share.streamlit.io/)
3. Click "New app"
4. Select your repository
5. Set main file path: `app.py`
6. Click "Deploy"

### Local Development

```bash
# Install dependencies
pip install streamlit pandas plotly

# Run the application
streamlit run app.py
```

## Usage

1. Upload a file using the file uploader
2. Configure analysis modules in the sidebar
3. Click "Start Analysis" to begin
4. View results in the interactive dashboard

## Technical Details

- **Framework**: Streamlit
- **Python Version**: 3.8+
- **Dependencies**: streamlit, pandas, plotly
- **Analysis Modules**: Hash calculation, entropy analysis, string extraction, pattern detection

## Security Note

This application performs static analysis only - no code execution occurs. Files are analyzed in memory and not stored permanently.

## Author

Built with 🛡️ by [Vishwas]