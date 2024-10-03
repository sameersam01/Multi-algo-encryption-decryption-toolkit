from Crypto.Cipher import AES
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog

# Caesar Cipher
def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if mode == 'decrypt':
                shift_amount = -shift_amount
            if char.islower():
                shifted_char = chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                shifted_char = chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
            result += shifted_char
        else:
            result += char
    return result

# Vigenère Cipher
def vigenere_cipher(text, key, mode):
    key = key.lower()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if mode == 'decrypt':
                shift = -shift
            if char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

# AES Cipher
def pad(text):
    block_size = 16
    pad_num = block_size - len(text) % block_size
    return text + pad_num * chr(pad_num)

def unpad(text):
    pad_num = ord(text[-1])
    return text[:-pad_num]

def aes_encrypt(text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text).encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text.encode('utf-8')))
    return unpad(decrypted.decode('utf-8'))

# GUI
def process_text():
    try:
        cipher_type = cipher_var.get()
        text = input_text.get("1.0", tk.END).strip()
        if cipher_type == 'Caesar':
            shift = int(shift_entry.get())
            if mode_var.get() == 'Encrypt':
                result = caesar_cipher(text, shift, 'encrypt')
            else:
                result = caesar_cipher(text, shift, 'decrypt')
        elif cipher_type == 'Vigenère':
            key = key_entry.get()
            if not key.isalpha():
                messagebox.showerror("Invalid Input", "Key must only contain alphabetic characters.")
                return
            if mode_var.get() == 'Encrypt':
                result = vigenere_cipher(text, key, 'encrypt')
            else:
                result = vigenere_cipher(text, key, 'decrypt')
        elif cipher_type == 'AES':
            key = key_entry.get()
            if len(key) != 16:
                messagebox.showerror("Invalid Input", "Key must be exactly 16 characters long.")
                return
            if mode_var.get() == 'Encrypt':
                result = aes_encrypt(text, key)
            else:
                result = aes_decrypt(text, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(output_text.get("1.0", tk.END).strip())

# Set up the main application window
root = tk.Tk()
root.title("Modern Cipher Tool")
root.configure(bg='#f0f0f0')

# Cipher type selection
cipher_var = tk.StringVar(value="Caesar")
cipher_frame = tk.LabelFrame(root, text="Select Cipher", bg='#e0e0e0', font=('Helvetica', 12, 'bold'))
cipher_frame.grid(row=0, column=0, padx=10, pady=10)
tk.Radiobutton(cipher_frame, text="Caesar", variable=cipher_var, value="Caesar", bg='#e0e0e0').pack(anchor="w")
tk.Radiobutton(cipher_frame, text="Vigenère", variable=cipher_var, value="Vigenère", bg='#e0e0e0').pack(anchor="w")
tk.Radiobutton(cipher_frame, text="AES", variable=cipher_var, value="AES", bg='#e0e0e0').pack(anchor="w")

# Mode selection
mode_var = tk.StringVar(value="Encrypt")
mode_frame = tk.LabelFrame(root, text="Mode", bg='#e0e0e0', font=('Helvetica', 12, 'bold'))
mode_frame.grid(row=0, column=1, padx=10, pady=10)
tk.Radiobutton(mode_frame, text="Encrypt", variable=mode_var, value="Encrypt", bg='#e0e0e0').pack(anchor="w")
tk.Radiobutton(mode_frame, text="Decrypt", variable=mode_var, value="Decrypt", bg='#e0e0e0').pack(anchor="w")

# Shift entry (for Caesar)
tk.Label(root, text="Shift (Caesar only):", bg='#f0f0f0').grid(row=1, column=0, padx=10, pady=10)
shift_entry = tk.Entry(root)
shift_entry.grid(row=1, column=1, padx=10, pady=10)

# Key entry (for Vigenère and AES)
tk.Label(root, text="Key (Vigenère & AES):", bg='#f0f0f0').grid(row=2, column=0, padx=10, pady=10)
key_entry = tk.Entry(root)
key_entry.grid(row=2, column=1, padx=10, pady=10)

# Input text area
tk.Label(root, text="Input Text:", bg='#f0f0f0').grid(row=3, column=0, padx=10, pady=10)
input_text = tk.Text(root, height=10, width=50, bg='#ffffff', font=('Arial', 10))
input_text.grid(row=3, column=1, padx=10, pady=10)

# Output text area
tk.Label(root, text="Output Text:", bg='#f0f0f0').grid(row=4, column=0, padx=10, pady=10)
output_text = tk.Text(root, height=10, width=50, bg='#ffffff', font=('Arial', 10))
output_text.grid(row=4, column=1, padx=10, pady=10)

# Process and copy buttons
process_button = tk.Button(root, text="Process", command=process_text, bg='#4CAF50', fg='white', font=('Helvetica', 10, 'bold'))
process_button.grid(row=5, column=0, padx=10, pady=10)
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, bg='#2196F3', fg='white', font=('Helvetica', 10, 'bold'))
copy_button.grid(row=5, column=1, padx=10, pady=10)

# Start the application
root.mainloop()
