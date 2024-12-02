# SecurityAnalyzr  

**SecurityAnalyzr** is a powerful file analysis tool designed for cybersecurity professionals to investigate suspicious files quickly and effectively. It integrates with VirusTotal and supports macro detection and phishing link analysis, providing comprehensive insights into potentially malicious attachments.

---

## **Features**
- **VirusTotal Integration**  
  Automatically checks file hashes against VirusTotal to identify malicious files and malware families.  

- **Macro Detection in Word Documents**  
  Detects macros in both `.doc` and `.docx` files, highlighting potential malicious scripts.  

- **Phishing Link Detection in PDFs**  
  Scans PDF files for suspicious URLs, helping identify potential phishing attempts.  

- **File Hashing**  
  Generates SHA-256 hashes of files for comparison against known threat databases.  

- **Real-Time Reporting**  
  Outputs detailed results, including MIME type, file hash, virus status, and malware family information.  

---

## **Requirements**
Before running **SecurityAnalyzr**, ensure you have the following installed:  
- Python 3.6+  
- Required Python libraries:  
  ```bash
  pip install requests pyfiglet PyPDF2 olefile


## **Installation**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ahmedkhalifa8474/SecurityAnalyzr.git

   cd SecurityAnalyzr

pip install -r requirements.txt

Usage

Run the script:

python SecurityAnalyzr.py

VirusTotal scan results.

Macro detection for Word files.

![image](https://github.com/user-attachments/assets/399b9208-405a-4025-aabf-72d087bb95aa)

![image](https://github.com/user-attachments/assets/ff0845cd-48c7-4560-a038-8193468d47e1)



Phishing link detection for PDFs.
