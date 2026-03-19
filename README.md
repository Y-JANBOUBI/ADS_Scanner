# ADS Scanner (Alternate Data Streams Detection)

**`ADS_Scanner`** Is a PowerShell script for detecting **`Alternate Data Streams (ADS)`** on NTFS file systems. ADS is a feature of NTFS that allows files to contain multiple data streams, which is often abused by attackers to hide malware, tools, or data on a compromised system. This Script enables security professionals and forensic analysts to scan drives (live or mounted forensic images) to identify hidden streams, inspect their content, and export findings for reporting.

---

## Prerequisites

* Windows PowerShell **5.1 or later** (PowerShell 7 supported)
* **Read access** to target directories
* **Administrator privileges** (recommended for full visibility)

---

## Installation

### Option 1: Clone the repository

```powershell
git clone https://github.com/YOUR_USERNAME/ADS_Scanner.git
cd ADS_Scanner
```

### Option 2: Download the script directly

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Y-JANBOUBI/ADS_Scanner/refs/heads/main/ADS_Scanner.ps1" -OutFile "ADS_Scanner.ps1"

```

---

## Usage
<img width="1080" height="412" alt="image" src="https://github.com/user-attachments/assets/ce1a6693-ba22-4cda-ba37-465adcf3df10" />


```powershell
.\ADS_Scanner.ps1 -Path <path> [-Csv <path>] [-Content] [-Format <Table|List>]
```

**Parameters:**

* `-Path` : The directory path to scan (Required).
* `-Csv` : Path to export results. Can be a directory (auto-names file) or a specific filename (Optional).
* `-Content` : Reads and previews the content of the ADS. Detects PE headers (EXE/DLL) and text data (Optional).
* `-Format` : Output display format. Options: `Table` (Default) or `List`.

**Examples:**

```powershell
# Basic scan of the C drive
.\ADS_Scanner.ps1 -Path "C:\"

# Scan a specific folder, enable content preview, and export to CSV
.\ADS_Scanner.ps1 -Path "D:\Forensics\Data" -Content -Csv "D:\Reports\Findings.csv"

# Scan a mounted forensic image and format output as a list
.\ADS_Scanner.ps1 -Path "E:\Mounted_Image" -Format List
```
<img width="1804" height="394" alt="image" src="https://github.com/user-attachments/assets/83d385b5-8d16-46a5-a9df-723ce62d6df1" />

---

## Output Details

The tool outputs the following fields for every detected stream:

* **File_Name**: The name of the visible file.
* **File_Path**: The full system path to the file.
* **Stream_Count**: Total number of streams attached to the file (1 = Normal, >1 = ADS present).
* **Second_ADS_Name**: The name of the hidden stream (e.g., `Zone.Identifier`).
* **Stream_Size_b**: Size of the hidden stream in bytes.
* **Content_Preview**: (Optional) A preview of the stream content.
    * Text streams (like Zone Identifiers) are displayed.
    * Binary/Executable streams are identified as `[PE_FILE] MZ Header Detected`.

---

## Post-Scan Verification

```powershell
# Manually check a specific file for streams
Get-Item -Path "C:\Temp\suspicious.txt" -Stream *

# Read the content of a specific stream
Get-Content -Path "C:\Temp\suspicious.txt:<Zone.Identifier|suspicious_stream_name>"
```
---
