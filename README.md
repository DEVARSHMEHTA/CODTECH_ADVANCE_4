# CODTECH_ADVANCE_4
# Advanced Encryption Tool
## Details
- Name    : Devarsh Mehta
- Company : CODTECH IT SOLUTIONS PVT.LTD
- ID      : CT08DAL
- Domain  : Cyber Security & Ethical Hacking
- Duration: 20th Dec 2024 To 20th Jan 2025
- Mentor  : Neela Santhosh Kumar

# Overview

The Advanced Encryption Tool is a Python-based application designed to provide a secure and user-friendly interface for file encryption and decryption. The application supports multiple hash algorithms and ensures robust encryption with AES-256.

## Features

- **File Encryption:** Encrypt files using AES-256 and various hash algorithms for key derivation.
- **File Decryption:** Decrypt previously encrypted files with the correct password and algorithm.
- **Hash Algorithm Selection:** Choose from SHA-1, SHA-256, SHA-512, and MD5.
- **Graphical User Interface (GUI):** Easy-to-use interface built with Tkinter.

## Requirements

- Python 3.6 or higher
- Libraries:
  - `cryptography`
  - `tkinter`
  - `pyfiglet`
  - `colorama`

Install the required libraries using pip:

```bash
pip install cryptography pyfiglet colorama
```

## How to Use

### Running the Application

1. Clone or download the repository.

```sh
git clone https://github.com/DEVARSHMEHTA/CODTECH_ADVANCE_4.git
```

2. Navigate to the directory containing the script.

```sh
cd CODTECH_ADVANCE_4
```

3. Give Executable Permissions.
```sh
chmod +x Crypto-tool.py
```


4. Run the script using Python:
```sh
python Crypto-tool.py
```

### Using the Application

1. Launch the application to see the main GUI.
2. Use the **Browse** button to select the file you want to encrypt or decrypt.
3. Enter a password for encryption or decryption.
4. Select a hash algorithm from the dropdown menu.
5. Click **Encrypt** to secure your file or **Decrypt** to retrieve the original file.

### File Encryption

- Encrypted files will be saved with a `.enc` extension in the same directory as the original file.

### File Decryption

- Decrypted files will be saved without the `.enc` extension, restoring the original filename.

## Technical Details

### Key Derivation

Keys are derived using the PBKDF2-HMAC algorithm with user-selected hash functions (SHA-1, SHA-256, SHA-512, or MD5). Salts and IVs are generated randomly to ensure security.

### AES Encryption

The tool uses AES encryption in CBC mode. Padding is applied to the plaintext to ensure compatibility with the AES block size.

### GUI

The GUI is built using Tkinter, providing a simple interface for file selection, password entry, and algorithm selection.

## Hash Algorithm Color Key

- **SHA-1:** Tomato Red
- **SHA-256:** Steel Blue
- **SHA-512:** Lime Green
- **MD5:** Gold

## Example Output
![image](https://github.com/user-attachments/assets/21e36430-85f5-4025-b33d-4821b7fba321)

![image](https://github.com/user-attachments/assets/d74652bf-1db6-4694-ae62-11a13465f296)

![image](https://github.com/user-attachments/assets/8cb9cfb4-f0b9-4ef2-b34e-cb332b1ed673)

### File Encryption

```
File encrypted: /path/to/file.txt.enc
```

### File Decryption

```
File decrypted: /path/to/file.txt
```

## Troubleshooting

- **Error during decryption:** Ensure the correct password and hash algorithm are used.
- **Invalid padding:** Indicates a mismatch in the decryption key or an altered file.

## Author

Created by Devarsh Mehta.

---
