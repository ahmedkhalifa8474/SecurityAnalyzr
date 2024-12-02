SecurityAnalyzr

SecurityAnalyzr is a powerful file analysis tool designed for cybersecurity professionals to investigate suspicious files quickly and effectively.

 It integrates with VirusTotal and supports macro detection and phishing link analysis, providing comprehensive insights into potentially malicious attachments.

Features

VirusTotal Integration

Automatically checks file hashes against VirusTotal to identify malicious files and malware families.

Macro Detection in Word Documents

Detects macros in both .doc and .docx files, highlighting potential malicious scripts.

Phishing Link Detection in PDFs

Scans PDF files for suspicious URLs, helping identify potential phishing attempts.

File Hashing

Generates SHA-256 hashes of files for comparison against known threat databases.

Real-Time Reporting

Outputs detailed results, including MIME type, file hash, virus status, and malware family information.

Requirements

Before running SecurityAnalyzr, ensure you have the following installed:

Python 3.6+

Required Python libraries
:
pip install requests pyfiglet PyPDF2 olefile
Installation

Clone the repository:

git clone https://github.com/ahmedkhalifa8474/SecurityAnalyzr.git

cd SecurityAnalyzr

Install the dependencies:

pip install -r requirements.txt

Update the VirusTotal API key in the script:

Open the SecurityAnalyzr.py file.

Replace the placeholder API_KEY with your own VirusTotal API key.
Usage

Run the script:

python SecurityAnalyzr.py

Input the full file path of the attachment you want to analyze.

View the analysis report, which will include:

File type and hash.

VirusTotal scan results.

Macro detection for Word files.

Phishing link detection for PDFs.
