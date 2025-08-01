import subprocess
import pandas as pd
import os
import argparse
import logging
import zipfile

# CLI argument parsing
parser = argparse.ArgumentParser(description='Windows Artifact Extractor')
parser.add_argument('--input', required=False, help='Path to mounted image, ZIP archive, or extracted folder (defaults to current directory)')
parser.add_argument('--output', required=True, help='Path to output report folder')
args = parser.parse_args()

# Logging setup
logging.basicConfig(filename='artifact_extractor.log', level=logging.INFO)

# Validate or set input path (defaults to current directory if not provided)
input_path = args.input if args.input else os.getcwd()
if not os.path.exists(input_path):
    logging.error(f"Input path does not exist: {input_path}")
    raise ValueError(f"Input path does not exist: {input_path}")

# ZIP extraction support
def extract_if_zip(input_path, temp_extract_folder):
    if input_path.lower().endswith(".zip") and os.path.isfile(input_path):
        logging.info(f"Extracting ZIP archive: {input_path}")
        with zipfile.ZipFile(input_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_folder)
        return temp_extract_folder
    return input_path

# Auto-detect artifact locations
def find_artifact_paths(root_path):
    artifact_paths = {
        'prefetch': None,
        'jumplists': None,
        'lnk': None,
        'shellbags': None,
        'mft': None,
        'registry': None
    }
    for root, _, files in os.walk(root_path):
        if 'Prefetch' in root and any(f.endswith('.pf') for f in files):
            artifact_paths['prefetch'] = root
        if 'AutomaticDestinations' in root and any(f.endswith('.automaticDestinations-ms') for f in files):
            artifact_paths['jumplists'] = root
        if 'Recent' in root and any(f.endswith('.lnk') for f in files):
            artifact_paths['lnk'] = root
        if 'NTUSER.DAT' in files:
            artifact_paths['shellbags'] = os.path.join(root, 'NTUSER.DAT')
        if any(f.startswith('$MFT') for f in files):
            artifact_paths['mft'] = os.path.join(root, next(f for f in files if f.startswith('$MFT')))
        if 'config' in root.lower() and any(f in files for f in ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY']):
            artifact_paths['registry'] = root
    return artifact_paths

# Handle ZIP extraction or use folder as-is
temp_folder = os.path.join(args.output, "unzipped_temp")
input_path = extract_if_zip(input_path, temp_folder)

# Find artifacts
artifact_paths = find_artifact_paths(input_path)

# Tool paths (hardcoded)
pecmd_path = r"D:\forensic\PECmd\PECmd.exe"
jlecmd_path = r"D:\forensic\JLECmd\JLECmd.exe"
lecmd_path = r"D:\forensic\LECmd\LECmd.exe"
mft_exe_path = r"D:\forensic\MFTECmd\MFTECmd.exe"
recmd_path = r"D:\forensic\RECmd\RECmd\RECmd.exe"

# Batch file paths for RECmd
batch_examples_dir = r"D:\forensic\RECmd\RECmd\BatchExamples"
batch_files = {
    'shellbags': os.path.join(batch_examples_dir, 'BatchExampleUserAssist.reb'),
    'registry': os.path.join(batch_examples_dir, 'RECmd_Batch_MC.reb')
}

# Output folders
pecmd_output_folder = os.path.join(args.output, "PrefetchOutput")
jlecmd_output_folder = os.path.join(args.output, "JumplistOutput")
lecmd_output_folder = os.path.join(args.output, "RecentOutput")
mft_output_folder = os.path.join(args.output, "$MFTOutput")
recmd_output_folder = os.path.join(args.output, "RegistryOutput")

# Create output folders
for folder in [pecmd_output_folder, jlecmd_output_folder, lecmd_output_folder, mft_output_folder, recmd_output_folder]:
    os.makedirs(folder, exist_ok=True)

# Run forensic tools with error handling
if artifact_paths['prefetch']:
    try:
        subprocess.run([pecmd_path, '-d', artifact_paths['prefetch'], '--csv', pecmd_output_folder], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running PECmd: {e}")

if artifact_paths['jumplists']:
    try:
        subprocess.run([jlecmd_path, '-d', artifact_paths['jumplists'], '--csv', jlecmd_output_folder], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running JLECmd: {e}")

if artifact_paths['lnk']:
    try:
        subprocess.run([lecmd_path, '-d', artifact_paths['lnk'], '--csv', lecmd_output_folder], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running LECmd: {e}")

if artifact_paths['mft']:
    try:
        subprocess.run([mft_exe_path, '-f', artifact_paths['mft'], '--csv', mft_output_folder], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running MFTECmd: {e}")

if artifact_paths['shellbags']:
    if not os.path.exists(recmd_path):
        logging.error(f"RECmd executable not found: {recmd_path}")
        raise FileNotFoundError(f"RECmd executable not found: {recmd_path}")
    if not os.path.exists(artifact_paths['shellbags']):
        logging.error(f"Shellbags file not found: {artifact_paths['shellbags']}")
        raise FileNotFoundError(f"Shellbags file not found: {artifact_paths['shellbags']}")
    if not os.path.exists(batch_files['shellbags']):
        logging.error(f"Shellbags batch file not found: {batch_files['shellbags']}")
        raise FileNotFoundError(f"Shellbags batch file not found: {batch_files['shellbags']}")
    try:
        subprocess.run([recmd_path, '-f', artifact_paths['shellbags'], '--bn', batch_files['shellbags'], '--csv', recmd_output_folder, '--nl', 'false'], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running RECmd (Shellbags): {e}")

if artifact_paths['registry']:
    if not os.path.exists(recmd_path):
        logging.error(f"RECmd executable not found: {recmd_path}")
        raise FileNotFoundError(f"RECmd executable not found: {recmd_path}")
    if not os.path.exists(batch_files['registry']):
        logging.error(f"Registry batch file not found: {batch_files['registry']}")
        raise FileNotFoundError(f"Registry batch file not found: {batch_files['registry']}")
    try:
        subprocess.run([recmd_path, '-d', artifact_paths['registry'], '--bn', batch_files['registry'], '--csv', recmd_output_folder, '--nl', 'false'], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running RECmd (Registry): {e}")

# Helper to read the first CSV file in a folder
def read_first_csv_in(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".csv"):
            return pd.read_csv(os.path.join(folder_path, filename), low_memory=False)
    raise FileNotFoundError(f"No CSV found in {folder_path}")

# Read tool outputs
try:
    df_pecmd = read_first_csv_in(pecmd_output_folder) if artifact_paths['prefetch'] else pd.DataFrame()
except FileNotFoundError as e:
    logging.error(f"Prefetch CSV error: {e}")
    df_pecmd = pd.DataFrame()

try:
    df_jlecmd = read_first_csv_in(jlecmd_output_folder) if artifact_paths['jumplists'] else pd.DataFrame()
except FileNotFoundError as e:
    logging.error(f"Jumplists CSV error: {e}")
    df_jlecmd = pd.DataFrame()

try:
    df_lecmd = read_first_csv_in(lecmd_output_folder) if artifact_paths['lnk'] else pd.DataFrame()
except FileNotFoundError as e:
    logging.error(f"LNK CSV error: {e}")
    df_lecmd = pd.DataFrame()

try:
    df_mftcmd = read_first_csv_in(mft_output_folder) if artifact_paths['mft'] else pd.DataFrame()
except FileNotFoundError as e:
    logging.error(f"MFT CSV error: {e}")
    df_mftcmd = pd.DataFrame()

try:
    df_recmd = read_first_csv_in(recmd_output_folder) if artifact_paths['shellbags'] or artifact_paths['registry'] else pd.DataFrame()
except FileNotFoundError as e:
    logging.error(f"RECmd CSV error: {e}")
    df_recmd = pd.DataFrame()

# Output report paths
report_excel_path = os.path.join(args.output, 'Final_Report.xlsx')
report_mft_csv_path = os.path.join(args.output, 'MFT_Output.csv')

# Save MFT output as separate CSV
if not df_mftcmd.empty:
    df_mftcmd.to_csv(report_mft_csv_path, index=False)

# Save the rest to Excel
with pd.ExcelWriter(report_excel_path) as writer:
    if not df_pecmd.empty:
        df_pecmd.to_excel(writer, sheet_name='Prefetch', index=False)
    if not df_jlecmd.empty:
        df_jlecmd.to_excel(writer, sheet_name='Jumplists', index=False)
    if not df_lecmd.empty:
        df_lecmd.to_excel(writer, sheet_name='LNK', index=False)
    if not df_recmd.empty:
        df_recmd.to_excel(writer, sheet_name='Registry', index=False)