import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import pyfiglet
from colorama import init

# Initialize colorama
init(autoreset=True)

# Function to derive a key from the password and salt using the chosen hash algorithm
def derive_key(password, salt, algorithm):
    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=32,  # AES-256 requires a 32-byte (256-bit) key
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

# Function to select the hash algorithm based on user input
def select_hash_algorithm(algo_name):
    algorithms_dict = {
        "SHA-1": hashes.SHA1(),
        "SHA-256": hashes.SHA256(),
        "SHA-512": hashes.SHA512(),
        "MD5": hashes.MD5()
    }
    return algorithms_dict.get(algo_name, None)

# Function to encrypt a file
def encrypt_file(filepath, password, algo_name):
    # Generate a random salt and IV (Initialization Vector)
    salt = os.urandom(16)
    iv = os.urandom(16)
    algorithm = select_hash_algorithm(algo_name)
    if algorithm is None:
        raise ValueError("Unsupported hash algorithm selected")
    
    key = derive_key(password, salt, algorithm)

    # Initialize AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read file content
    with open(filepath, 'rb') as file:
        plaintext = file.read()

    # Apply padding (AES block size is 16 bytes)
    padding_length = 16 - len(plaintext) % 16
    padded_plaintext = plaintext + bytes([padding_length]) * padding_length

    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the encrypted file (salt + IV + ciphertext)
    encrypted_filepath = filepath + '.enc'
    with open(encrypted_filepath, 'wb') as file:
        file.write(salt + iv + ciphertext)
    
    return encrypted_filepath

# Function to decrypt a file
def decrypt_file(filepath, password, algo_name):
    try:
        # Read the encrypted file content
        with open(filepath, 'rb') as file:
            content = file.read()
        
        # Extract salt, IV, and ciphertext from the encrypted file
        salt, iv, ciphertext = content[:16], content[16:32], content[32:]
        
        # Generate the decryption key using the password, salt, and selected hash algorithm
        algorithm = select_hash_algorithm(algo_name)
        if algorithm is None:
            raise ValueError("Unsupported hash algorithm selected")
        
        key = derive_key(password, salt, algorithm)
        
        # Initialize AES cipher in CBC mode for decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = padded_plaintext[-1]
        if not (1 <= padding_length <= 16):
            raise ValueError("Invalid padding")
        
        plaintext = padded_plaintext[:-padding_length]

        # Save the decrypted file
        decrypted_filepath = filepath.replace('.enc', '')
        with open(decrypted_filepath, 'wb') as file:
            file.write(plaintext)
        
        return decrypted_filepath
    
    except Exception as e:
        raise ValueError(f"Error during decryption: {str(e)}")

# GUI Function to handle encryption/decryption based on user input
def handle_encryption_decryption(action):
    # Retrieve user inputs from GUI
    filepath = file_path_var.get()
    password = password_var.get()
    algo_name = algo_var.get()

    if not filepath or not password or not algo_name:
        messagebox.showerror("Error", "Please provide file path, password, and hash algorithm.")
        return

    try:
        if action == 'encrypt':
            encrypted_filepath = encrypt_file(filepath, password, algo_name)
            messagebox.showinfo("Success", f"File encrypted: {encrypted_filepath}")
        elif action == 'decrypt':
            decrypted_filepath = decrypt_file(filepath, password, algo_name)
            messagebox.showinfo("Success", f"File decrypted: {decrypted_filepath}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Layout Function to create the main window
def create_main_window():
    window = tk.Tk()
    window.title("Advanced Encryption Tool")
    window.config(bg="#2e3b4e")  # Dark background color
    window.geometry("400x500")

    # Display logo using pyfiglet
    logo_text = pyfiglet.figlet_format("CryptoTool")
    logo_label = tk.Label(window, text=logo_text, font=("Courier", 12), fg="white", bg="#2e3b4e")
    logo_label.pack(pady=10)

    # File Path Input
    global file_path_var
    file_path_var = tk.StringVar()
    file_path_label = tk.Label(window, text="File Path:", fg="white", bg="#2e3b4e")
    file_path_label.pack(pady=5)
    file_path_entry = tk.Entry(window, textvariable=file_path_var, width=40)
    file_path_entry.pack(pady=5)

    # Browse Button to select file
    def browse_file():
        selected_file = filedialog.askopenfilename()
        file_path_var.set(selected_file)

    browse_button = tk.Button(window, text="Browse", command=browse_file, width=20, bg="#5a5a5a", fg="white")
    browse_button.pack(pady=5)

    # Password Input
    global password_var
    password_var = tk.StringVar()
    password_label = tk.Label(window, text="Password:", fg="white", bg="#2e3b4e")
    password_label.pack(pady=5)
    password_entry = tk.Entry(window, textvariable=password_var, show="*", width=40)
    password_entry.pack(pady=5)

    # Hash Algorithm Dropdown Menu with colors
    global algo_var
    algo_var = tk.StringVar()
    algo_var.set("SHA-256")  # Default value
    algo_label = tk.Label(window, text="Hash Algorithm:", fg="white", bg="#2e3b4e")
    algo_label.pack(pady=5)
    
    # Options with specific colors
    options = [
        ("SHA-1", "#FF6347"),
        ("SHA-256", "#4682B4"),
        ("SHA-512", "#32CD32"),
        ("MD5", "#FFD700")
    ]

    algo_menu = tk.OptionMenu(window, algo_var, *map(lambda option: option[0], options))
    algo_menu.configure(bg="#5a5a5a", fg="white", width=20)
    algo_menu.pack(pady=5)

    # Encrypt Button
    encrypt_button = tk.Button(window, text="Encrypt", command=lambda: handle_encryption_decryption('encrypt'), width=20, bg="#5a5a5a", fg="white")
    encrypt_button.pack(pady=10)

    # Decrypt Button
    decrypt_button = tk.Button(window, text="Decrypt", command=lambda: handle_encryption_decryption('decrypt'), width=20, bg="#5a5a5a", fg="white")
    decrypt_button.pack(pady=10)

    # Owner Information
    owner_label = tk.Label(window, text="Created by Devarsh Mehta", fg="white", bg="#2e3b4e")
    owner_label.pack(side=tk.BOTTOM, pady=10)

    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    create_main_window()
