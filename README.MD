# Chrome Password Extractor

## ⚠️ Warning
**This script is for educational and ethical purposes only.** Unauthorized use of this script to extract saved passwords from a user's browser without their consent is illegal and violates privacy laws. Use it only with permission or for personal data recovery. Misuse of this tool may result in legal consequences, including criminal charges. Always ensure you have the necessary authorization before proceeding.

---

## 📌 Overview
Google Chrome stores user credentials in an encrypted format within an SQLite database. This script extracts, decrypts, and saves those credentials for authorized recovery or educational purposes. It leverages the **Windows DPAPI (Data Protection API)** to decrypt the stored AES-encrypted passwords and provides the data in a structured format.

The script follows these steps:
- Identifies and retrieves the encryption key stored in Chrome's `Local State` file.
- Uses **Windows DPAPI** to decrypt the extracted encryption key.
- Copies the SQLite database containing login credentials (`Login Data`) from Chrome’s user directory.
- Extracts saved login credentials (URLs, usernames, encrypted passwords) from the database.
- Decrypts the stored passwords using the extracted AES encryption key.
- Saves the credentials in a formatted text file (`browser_passwords.txt`).
- Hides the output file for additional security.

This process allows users to recover their credentials from Chrome, but it should only be used in legal and ethical scenarios.

---

## 🛠 Features
- **Automated Extraction:** Retrieves Chrome's saved login credentials without manual intervention.
- **AES-GCM Decryption:** Uses advanced cryptographic methods to decrypt stored passwords.
- **Windows DPAPI Integration:** Ensures seamless decryption of Chrome’s encryption key.
- **User-Friendly Output:** Extracted credentials are saved in a structured format.
- **File Concealment:** Automatically hides the output file to prevent unauthorized access.
- **Error Handling:** Built-in exception handling prevents script failure due to missing files or incorrect decryption.

---

## 🔧 Requirements
### **Python Dependencies**
Ensure you have the required Python libraries installed before running the script:
```bash
pip install pycryptodome pypiwin32
```
These libraries are necessary for decryption and interacting with Windows APIs.

### **System Requirements**
- **Windows OS** (The script relies on `CryptUnprotectData` from `win32crypt`, which is exclusive to Windows systems.)
- **Google Chrome Installed** (The script extracts data from Chrome’s default profile directory.)

### **Required Permissions**
To access Chrome’s user data, the script must be run with an account that has sufficient privileges to read from `AppData`. If permissions are restricted, running the script as an administrator may be required.

---

## 📜 How It Works
1. **Retrieving the Encryption Key**
   - Chrome encrypts stored passwords using an **AES key** stored in the `Local State` file.
   - The script extracts and decrypts this key using **Windows DPAPI**.

2. **Copying Chrome’s Login Database**
   - Chrome locks its SQLite database while in use, so the script creates a temporary copy of `Login Data`.
   - This ensures smooth extraction without interfering with Chrome’s active processes.

3. **Extracting Credentials**
   - The script connects to the copied SQLite database and extracts login information.
   - Data retrieved includes:
     - `origin_url` (Website URL)
     - `username_value` (Saved username)
     - `password_value` (Encrypted password)

4. **Decrypting Stored Passwords**
   - Using the extracted AES key, the script decrypts each stored password using **AES-GCM mode**.
   - The decrypted credentials are formatted for readability.

5. **Saving and Hiding the Output File**
   - The extracted credentials are written to `browser_passwords.txt`.
   - The script then hides the file to prevent easy access.

6. **Error Handling**
   - If any step fails (e.g., missing files, permission issues, failed decryption), the script catches the error and provides a relevant message.

---

## 🚀 Usage
### **Running the Script**
```bash
python script.py
```
Upon execution, the script extracts, decrypts, and saves Chrome passwords in `browser_passwords.txt`.

### **Sample Output Format**
```
URL: https://example.com
Username: user@example.com
Password: mysecurepassword

URL: https://another-site.com
Username: anotheruser
Password: anotherpassword
```

### **Locating the Output File**
By default, the extracted credentials are saved in the script’s working directory. If you cannot find `browser_passwords.txt`, enable the display of hidden files in Windows:
1. Open **File Explorer**.
2. Click on the **View** tab.
3. Check **Hidden Items** to reveal hidden files.

---

## 📁 File Structure
```
.
├── script.py                  # Main Python script
├── README.md                  # Documentation
└── browser_passwords.txt      # Output file (hidden)
```

---

## ❗ Important Considerations
### **Security Risks**
- Running this script on a shared or public machine may expose sensitive data.
- Extracted credentials are stored in plaintext, making them vulnerable to theft.
- The script does not exfiltrate data, but malicious users could modify it for unauthorized access.

### **Preventing Unauthorized Access**
- Regularly clear saved passwords in Chrome.
- Use a **password manager** instead of relying on browser storage.
- Enable **multi-factor authentication (MFA)** for critical accounts.
- Restrict access to Chrome’s user data folder (`%AppData%\Local\Google\Chrome\User Data`).

---

## ⚠️ Legal Disclaimer
This script is intended for **ethical use only**. Unauthorized access to stored credentials without consent is illegal under multiple privacy laws, including:
- **Computer Fraud and Abuse Act (CFAA) – U.S.**
- **General Data Protection Regulation (GDPR) – EU**
- **Data Protection Act 2018 – UK**
- **Personal Data Protection Laws – Various Countries**

Use this tool only for legal and ethical purposes, such as recovering your own credentials or conducting authorized security assessments. **Misuse may result in criminal charges.**

**🔹 Always obtain proper authorization before using this script.**

