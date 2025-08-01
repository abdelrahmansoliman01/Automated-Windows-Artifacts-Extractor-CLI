# Windows Artifact Extractor

## Overview
The Windows Artifact Extractor is a forensic tool that automates the extraction of key Windows artifacts from a mounted disk image, ZIP archive, or folder. It leverages command-line forensic tools such as **PECmd**, **JLECmd**, **LECmd**, **MFTECmd**, and **SBECmd** to extract artifacts like Prefetch files, Jumplists, LNK files, the MFT, and registry artifacts. The tool consolidates the parsed outputs into structured CSV and Excel reports for further forensic analysis.

## Features
- Automated Artifact Extraction: Processes Prefetch, Jumplists, Shellbags, LNK files, MFT, and Registry data.
- Flexible Input Types: Supports mounted disk images, ZIP archives, or extracted folders.
- CSV and Excel Reporting: Consolidates outputs into a Final_Report.xlsx and separate CSVs (e.g., MFT_Output.csv).
- Error Handling & Logging: Logs any execution issues in `logs/run.log`.
- Auto-Detection of Artifact Locations: Uses a helper function to automatically locate standard artifact directories.

## Project Structure
```
WindowsArtifactExtractor/
│
├── extractor.py       # Main script for artifact extraction
├── utils.py           # Utility functions (if needed for additional functionality)
├── README.md          # This file
├── requirements.txt   # Python dependencies
├── logs/
│   └── run.log        # Log file for runtime messages/errors
└── output/
    ├── MFT_Output.csv # CSV output for MFT artifacts
    └── Final_Report.xlsx # Consolidated report of extracted artifacts
```

## Installation

1. **Prerequisites**
   - Python 3.x installed on your system.
   - Forensic command-line tools (PECmd, JLECmd, LECmd, MFTECmd, SBECmd) are installed and accessible.

2. **Clone or Download the Repository**
   Download or clone this repository to your local machine.

3. **Install Dependencies**
   Navigate to the project directory and run:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the extractor:
```bash
python extractor.py --input "D:/Path/To/Artifacts.zip" --output "D:/Path/To/output"
```

- `--input`: Path to the mounted disk image, ZIP archive, or extracted folder containing Windows artifacts.
- `--output`: Path to the directory where the final reports will be generated.

### Testing ZIP Files
If you have a ZIP archive, the script will automatically extract it to a temporary folder inside your output directory (`unzipped_temp`) and proceed with artifact extraction.

## Logging
Check the `logs/run.log` file for any errors or warnings during execution.

## Authors
- Abdelrahman Mohamed Mahmoud
- Nour Mohamed Mahmoud
- Adham Hamada
- Ahmed Sherif
- Mohamed Hesham