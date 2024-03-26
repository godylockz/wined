#!/bin/bash

# Constants
PS_SCRIPT_PATH="\\\\tsclient\\share\wined\\install.ps1"

# Define the vscode extensions to be downloaded
VSCODE_EXTENSIONS=(
    "ms-python.python"
    "njpwerner.autodocstring"
    "KevinRose.vsc-python-indent"
    "ms-python.black-formatter"
    "ms-python.vscode-pylance"
    "mgesbert.python-path"
)

# Define the python extensions to be downloaded
PYTHON_EXTENSIONS=(
    "keystone-engine"
    "capstone"
)

# Define the installers to be downloaded
INSTALLERS=(
    "https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip pykd.zip"
    "https://github.com/corelan/windbglib/raw/master/windbglib.py windbglib.py"
    "https://github.com/corelan/mona/raw/master/mona.py mona.py"
    "https://www.python.org/ftp/python/2.7.18/python-2.7.18.msi python-2.7.18.msi"
    "https://www.python.org/ftp/python/3.11.8/python-3.11.8.exe python-3.11.8.exe"
    "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe vcredist_x86_2008.exe"
    "https://download.visualstudio.microsoft.com/download/pr/10912113/5da66ddebb0ad32ebd4b922fd82e8e25/vcredist_x86.exe vcredist_x86_2013.exe"
    "https://aka.ms/vs/17/release/VC_redist.x86.exe vcredist_x86_2015.exe"
    "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe vcredist_x64_2008.exe"
    "https://download.visualstudio.microsoft.com/download/pr/10912041/cee5d6bca2ddbcd039da727bf4acb48a/vcredist_x64.exe vcredist_x64_2013.exe"
    "https://aka.ms/vs/17/release/VC_redist.x64.exe vcredist_x64_2015.exe"
    "https://update.code.visualstudio.com/latest/win32-x64/stable vscode_x64.exe"
    "https://update.code.visualstudio.com/latest/win32/stable vscode_x86.exe"
    "https://go.microsoft.com/fwlink/?linkid=2237387 winsdksetup.exe"
    "https://download.sysinternals.com/files/SysinternalsSuite.zip sysinternals.zip"
    "https://github.com/winsiderss/si-builds/releases/download/3.0.7479/systeminformer-3.0.7479-setup.exe systeminformer_x64.exe"
    "https://out7.hex-rays.com/files/idafree84_windows.exe idafree_x64.exe"
)

# Initially - Windows SDK 10.0.18362.1
# Windows 10 SDK version 2104 (10.0.20348.0) - https://go.microsoft.com/fwlink/?linkid=2164145
# Windows SDK for Windows 11 (10.0.22621.1778) - https://go.microsoft.com/fwlink/?linkid=2237387

# Check dependencies
for dependency in jq wget unzip; do
    if ! command -v "$dependency" &>/dev/null; then
        echo "Error: $dependency is not installed. Please install it before running the script."
        exit 1
    fi
done

# Function to check file existence
file_exists() {
    [ -e "$1" ]
}

# Create an installers directory
INSTALLDIR="../wininstallers"
if [ ! -d "$INSTALLDIR" ]; then
    echo "Directory $INSTALLDIR does not exist. Please create it."
    mkdir $INSTALLDIR
fi

# Function to download VS marketplace extension
get_vs_marketplace_extension() {
    local extensionName="$1"
    local body="{\"filters\":[{\"criteria\":[{\"filterType\":7,\"value\":\"$extensionName\"}]}],\"flags\":1712}"
    
    local response
    response=$(curl -s -X POST -H "Content-Type: application/json" -d "$body" "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=6.0-preview")
    if ! jq 'has("results")' <<< "$response" &>/dev/null; then
        echo "API Error: $response"
        return
    fi

    local extension
    extension=$(echo "$response" | jq -r '.results[0].extensions[0]')
    if [ "$extension" == "null" ] || [ "$extension" == "[]" ]; then
        echo "Extension not found"
        return
    fi

    local publisher
    publisher=$(echo "$extension" | jq -r '.publisher.publisherName')
    local extensionName
    extensionName=$(echo "$extension" | jq -r '.extensionName')
    local version
    version=$(echo "$extension" | jq -r '.versions[0].version')

    # Check if any essential information is missing
    if [ -z "$publisher" ] || [ -z "$extensionName" ] || [ -z "$version" ]; then
        echo "[-] Essential information missing for $extensionName"
        return
    fi

    local url
    url=$(echo "$extension" | jq -r '.versions[0].assetUri')"/Microsoft.VisualStudio.Services.VSIXPackage"

    echo "[*] Downloading $publisher.$extensionName.$version"
    wget --timestamping -q "$url" -O "$INSTALLDIR/$extensionName.vsix"
}

# Download each installer to the target directory
for installer in "${INSTALLERS[@]}"; do
    url=$(echo "$installer" | cut -d' ' -f1)
    filename=$(echo "$installer" | cut -d' ' -f2)
    
    # Check if the file already exists
    if file_exists "$INSTALLDIR/$filename"; then
        echo "[*] $filename exists - overwriting"
    fi
    echo "[*] Downloading $filename"
    wget --timestamping -q "$url" -O "$INSTALLDIR/$filename"
done

# Extract the contents of pykd.zip
if file_exists "$INSTALLDIR/pykd.zip"; then
    unzip -qqjo "$INSTALLDIR/pykd.zip" "pykd.pyd" -d "$INSTALLDIR"
    rm -rf "$INSTALLDIR/pykd.zip"
else
    echo "[*] pykd.zip not found. Please ensure it is downloaded."
fi

# Download VS Code marketplace extensions
for extension in "${VSCODE_EXTENSIONS[@]}"; do
    get_vs_marketplace_extension "$extension"
done

# Download Python3 extensions
for extension in "${PYTHON_EXTENSIONS[@]}"; do
    pip3 download --platform=win32 --no-deps --dest="$INSTALLDIR" "$extension"
done

# Output instructions for the user
echo "[*] Execute the following command in an Administrator terminal:"
echo "powershell -ExecutionPolicy Bypass -File $PS_SCRIPT_PATH"