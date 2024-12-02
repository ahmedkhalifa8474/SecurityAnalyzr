import hashlib
import requests
import re
import mimetypes
import os
import olefile
from zipfile import ZipFile
from PyPDF2 import PdfReader
import pyfiglet

# VirusTotal API Key
API_KEY = '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$6f690c0bf819d556e0c'

# Function to display ASCII banner
def display_banner():
    """
    Display ASCII art banner with author info.
    """
    banner = pyfiglet.figlet_format("SecurityAnalyzr")
    author_info = """
    Author: Kh4lifa0x
    LinkedIn: www.linkedin.com/in/ahmed-khalifa-849404266
    """
    print(banner + author_info)

# Function to check if a file contains a hash and return it
def extract_hash_from_text(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            # Regex to detect common hash patterns (MD5, SHA-1, SHA-256)
            hash_pattern = r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
            hashes = re.findall(hash_pattern, content)
            if hashes:
                return hashes[0]  # Return the first hash found
    except Exception as e:
        print(f"Error reading text file: {e}")
    return None

# Function to check the file hash on VirusTotal and get additional malware details
def check_virus_total(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            analysis_results = data['data']['attributes']['last_analysis_stats']
            if analysis_results['malicious'] > 0:
                # Get malware family and other names if available
                malware_info = data['data']['attributes'].get('popular_threat_classification', {})
                malware_family = malware_info.get('suggested_family', 'Unknown Family')
                additional_names = malware_info.get('names', [])
                if not malware_family and not additional_names:  # Fallback if neither is available
                    malware_family = 'Unknown'
                    additional_names = []
                return "Malicious", malware_family, additional_names
            elif analysis_results['suspicious'] > 0:
                return "Suspicious", None, None
            else:
                return "Normal", None, None
    return "Error checking hash", None, None

# Function to get file hash
def get_file_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            return file_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file for hash: {e}")
    return None

# Function to check if a Word document has macros
def check_word_macros(file_path):
    try:
        # Handle .doc (old Word format) using olefile
        if file_path.endswith(".doc"):
            try:
                ole = olefile.OleFileIO(file_path)
                if ole.exists('Macros'):
                    return True  # Return True if macros are found
                else:
                    return False  # Return False if no macros are found
            except OSError as e:
                print(f"Error checking macros in .doc file: {e}")
                return False

        # Handle .docx (new Word format) using ZipFile (since .docx is a zip archive)
        if file_path.endswith(".docx"):
            with ZipFile(file_path, 'r') as docx_zip:
                # Check if there is a 'word/vbaProject.bin' file which indicates macros
                if 'word/vbaProject.bin' in docx_zip.namelist():
                    return True  # Return True if macros are found
                else:
                    return False  # Return False if no macros are found
    except Exception as e:
        print(f"Error checking macros in Word file: {e}")
    
    return False  # Return False if no macros are found

# Function to check for phishing in PDF (URLs in this case)
def check_pdf_for_phishing(file_path):
    try:
        reader = PdfReader(file_path)
        for page in reader.pages:
            content = page.extract_text()
            urls = re.findall(r'http[s]?://\S+', content)
            if urls:
                return True  # Return True if any URL is found
    except Exception as e:
        print(f"Error reading PDF for phishing: {e}")
    return False

# Function to analyze the file
def analyze_file(file_path):
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"File does not exist: {file_path}")
        return

    # Get MIME type of the file
    mime_type, _ = mimetypes.guess_type(file_path)
    print(f"File MIME Type: {mime_type}")

    # Get file hash and check it on VirusTotal
    file_hash = get_file_hash(file_path)
    if file_hash:
        print(f"File Hash: {file_hash}")
        result, malware_family, additional_names = check_virus_total(file_hash)
        print(f"VirusTotal Status: {result}")
        if result == "Malicious":
            print(f"Malware Family: {malware_family}")
            if additional_names:
                print(f"Other Names: {', '.join(additional_names)}")
    else:
        print("Error getting file hash.")

    # Check if the file has macros (for Word files)
    if mime_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
        if check_word_macros(file_path):
            print("Warning: Word file contains macros!")
        else:
            print("No macros found in the Word file.")

    # Check for phishing links in PDFs
    elif mime_type == 'application/pdf':
        if check_pdf_for_phishing(file_path):
            print("Warning: PDF file contains potential phishing links.")
        else:
            print("No phishing links found in the PDF.")

if __name__ == "__main__":
    # Display the banner
    display_banner()

    # Input from the user for the file path
    file_path = input("Enter the full file path of the attachment to analyze: ").strip()
    analyze_file(file_path)
