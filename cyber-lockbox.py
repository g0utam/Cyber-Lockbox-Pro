import os
import tkinter as tk
from tkinter import filedialog, messagebox
from getpass import getpass
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ════════════════════════════════════════════════════════════════════
# 🔐 CYBER LOCKBOX PRO
# Author: g0utam
# Description: AES-256 GCM file encryption/decryption with PBKDF2.
# ════════════════════════════════════════════════════════════════════

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key using PBKDF2 (SHA256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_path: str, output_name: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_data = salt + iv + tag + ciphertext

    folder = os.path.dirname(input_path)
    output_path = os.path.join(folder, output_name + ".enc")

    with open(output_path, "wb") as f:
        f.write(encrypted_data)

    return output_path


def decrypt_file(input_path: str, output_name: str, password: str):
    with open(input_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    ciphertext = data[44:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    folder = os.path.dirname(input_path)
    output_path = os.path.join(folder, output_name + ".txt")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return output_path


# --- GUI Functions ---
def browse_file():
    file_path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, file_path)


def process(action):
    file_path = entry_file.get()
    output_name = entry_output.get()
    password = entry_pass.get()

    if not file_path or not output_name or not password:
        messagebox.showwarning("Missing Info", "Please fill all fields.")
        return

    try:
        if action == "encrypt":
            output_path = encrypt_file(file_path, output_name, password)
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as:\n{output_path}")
        else:
            output_path = decrypt_file(file_path, output_name, password)
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as:\n{output_path}")

        # ✅ Clear all fields after successful operation
        entry_file.delete(0, tk.END)
        entry_output.delete(0, tk.END)
        entry_pass.delete(0, tk.END)

    except Exception as e:
        messagebox.showerror("Error", f"Operation failed!\n{e}")

        # ✅ Also clear password field even if an error occurs
        entry_pass.delete(0, tk.END)



# --- Build GUI ---
root = tk.Tk()
root.title("🔐 Cyber Lockbox Pro")
root.geometry("480x340")
root.resizable(False, False)
root.configure(bg="#1e1e1e")

title = tk.Label(root, text="CYBER LOCKBOX PRO", font=("Arial", 18, "bold"), fg="#00e6ac", bg="#1e1e1e")
title.pack(pady=10)

frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(pady=10)

# File input
tk.Label(frame, text="Select File:", fg="white", bg="#1e1e1e").grid(row=0, column=0, sticky="w", pady=5)
entry_file = tk.Entry(frame, width=40)
entry_file.grid(row=0, column=1, padx=5)
tk.Button(frame, text="Browse", command=browse_file, bg="#00e6ac").grid(row=0, column=2)

# Output name
tk.Label(frame, text="Output Name:", fg="white", bg="#1e1e1e").grid(row=1, column=0, sticky="w", pady=5)
entry_output = tk.Entry(frame, width=40)
entry_output.grid(row=1, column=1, padx=5)

# Password
tk.Label(frame, text="Password:", fg="white", bg="#1e1e1e").grid(row=2, column=0, sticky="w", pady=5)
entry_pass = tk.Entry(frame, show="*", width=40)
entry_pass.grid(row=2, column=1, padx=5)

# Buttons
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=20)

tk.Button(button_frame, text="🔒 Encrypt", width=15, bg="#00cc66", command=lambda: process("encrypt")).grid(row=0, column=0, padx=10)
tk.Button(button_frame, text="🔓 Decrypt", width=15, bg="#0099ff", command=lambda: process("decrypt")).grid(row=0, column=1, padx=10)

footer = tk.Label(root, text="Developed by g0utam | AES-256 Secure", font=("Arial", 9), fg="gray", bg="#1e1e1e")
footer.pack(side="bottom", pady=10)

root.mainloop()
