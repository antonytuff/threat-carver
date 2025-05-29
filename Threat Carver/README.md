# MITRE ATT&CK Explorer

![MITRE Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/3/32/MITRE_logo.svg/1200px-MITRE_logo.svg.png)

## Overview

MITRE ATT&CK Explorer is a Streamlit-based web application that allows cybersecurity professionals to explore and analyze the MITRE ATT&CK framework. This tool provides an interactive interface to examine threat actor techniques, tactics, and procedures (TTPs) used in cyber attacks.

## Features

- **Group Analysis**: Explore techniques used by specific threat groups
  - Filter by tactics
  - Search for specific techniques
  - Visualize tactics distribution
  - View detailed information about each technique

- **Technique Explorer**: Search and browse all techniques in the ATT&CK framework
  - Find techniques by ID, name, or description
  - View detailed information about each technique
  - See which threat groups use specific techniques

- **Technique Replication**: Find and implement specific techniques in a controlled environment
  - Access Atomic Red Team tests for MITRE ATT&CK techniques
  - View detailed implementation steps and commands for each technique
  - Get platform-specific dependencies and execution instructions
  - Replicate techniques safely in your own environment for testing and training

- **Technique Replication**: Find and replicate techniques in a controlled environment
  - Search for specific techniques to test
  - View Atomic Red Team tests for selected techniques
  - Get detailed implementation instructions

- **About MITRE ATT&CK**: Learn more about the framework and its applications

## Requirements

- Python 3.7+
- Streamlit
- Pandas
- Plotly
- Requests
- PyYAML

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/antonytuff/MITRE_ATT-CK_Explorer.git
   cd MITRE_ATT-CK_Explorer
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   streamlit run app.py
   ```

## Usage

After launching the application, you can:

1. Select a page from the sidebar navigation
2. On the Group Analysis page:
   - Choose a threat group from the dropdown
   - Filter by tactics if needed
   - Use the search bar to find specific techniques
   - View the detailed information and download as CSV or JSON
3. On the Technique Explorer page:
   - Search for techniques by ID, name, or description
   - Select a technique to view its details and the groups that use it
4. On the Technique Replication page:
   - Search for techniques to replicate
   - View Atomic Red Team tests for the selected technique
   - Get detailed implementation steps, commands, and dependencies
   - Execute and clean up tests in your controlled environment

## Data Sources

The application uses the following data sources:
- MITRE CTI (Cyber Threat Intelligence) Repository: Provides the latest ATT&CK framework data in JSON format
- Atomic Red Team Repository: Provides implementation tests for MITRE ATT&CK techniques

## Screenshots

*Coming soon*

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTI Repository](https://github.com/mitre/cti)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Streamlit](https://streamlit.io/)
