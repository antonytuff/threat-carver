# Threat Carver Setup Instructions

## Overview
Threat Carver is a powerful threat intelligence tool that leverages the MITRE ATT&CK® framework to provide surgical precision in analyzing adversary tactics and techniques.

## Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. **Navigate to the Threat Carver directory:**
   ```bash
   cd "Threat Carver"
   ```

2. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   streamlit run app.py
   ```

   Or on Windows, simply double-click `run_threat_carver.bat`

## Features

### 🔪 Threat Carver Capabilities:
- **Group Analysis**: Examine the techniques used by specific threat groups
- **Technique Explorer**: Search and browse all techniques in the framework
- **Technique Replication**: Find specific techniques and view Atomic Red Team tests
- **About Attack Framework**: Learn more about the MITRE ATT&CK framework

### 📊 What's New:
- **Separated CSS**: All styling has been moved to `styles.css` for better maintainability
- **Professional UI**: Clean, modern interface with surgical precision theming
- **Enhanced Search**: Advanced filtering and search capabilities
- **Export Options**: Download data as CSV or JSON formats
- **Interactive Visualizations**: Charts and graphs for better data understanding

## File Structure
```
Threat Carver/
├── app.py                    # Main application file
├── styles.css               # External CSS styling
├── technique_replication.py  # Technique replication module
├── requirements.txt         # Python dependencies
├── run_threat_carver.bat    # Windows batch file to run the app
├── SETUP.md                 # This setup file
├── README.md                # Project documentation
└── LICENSE                  # License information
```

## Usage

1. **Start the application** using one of the methods above
2. **Open your web browser** and navigate to the URL shown in the terminal (usually `http://localhost:8501`)
3. **Explore threat intelligence** using the sidebar navigation:
   - Select different pages from the radio buttons
   - Use search functionality to find specific techniques or groups
   - Filter by tactics to narrow down results
   - Download data for offline analysis

## Troubleshooting

### Common Issues:
- **Port already in use**: If port 8501 is busy, Streamlit will automatically use the next available port
- **Missing dependencies**: Run `pip install -r requirements.txt` to install all required packages
- **Python version**: Ensure you're using Python 3.7 or higher

### Performance Tips:
- The application caches MITRE ATT&CK data to improve performance
- First load may take a few seconds to download the latest data
- Subsequent loads will be much faster due to caching

## Support
For issues or questions, refer to the README.md file or check the MITRE ATT&CK documentation at https://attack.mitre.org/

---
**Threat Carver** - Dissect, analyze and expose threat actor techniques with surgical precision 🔪
