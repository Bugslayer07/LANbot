import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Server Connection Settings
SERVER_IP = "192.168.137.1"  # Change to your server's LAN IP
SERVER_PORT = 12345

# AES Encryption Setup
SECRET_KEY = b"thisisaverysecur"  # Must be 16, 24, or 32 bytes
cipher = Cipher(algorithms.AES(SECRET_KEY), modes.ECB(), backend=default_backend())

def encrypt_message(message):
    """Encrypts a message using AES."""
    padded_message = message.ljust(16)[:16].encode()  # Ensure message is 16 bytes
    encryptor = cipher.encryptor()
    return encryptor.update(padded_message) + encryptor.finalize()

def decrypt_message(encrypted_msg):
    """Decrypts an AES encrypted message."""
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_msg).decode().strip()

def receive_messages():
    """Receives messages from the server."""
    while True:
        try:
            encrypted_msg = client_socket.recv(1024)
            if not encrypted_msg:
                break
            message = decrypt_message(encrypted_msg)
            chat_area.insert(tk.END, message + "\n")
        except:
            break

def send_message():
    """Sends an encrypted message to the server."""
    msg = message_entry.get()
    if msg:
        encrypted_msg = encrypt_message(username + ": " + msg)
        try:
            client_socket.send(encrypted_msg)
        except:
            chat_area.insert(tk.END, "Error: Connection lost.\n")
        message_entry.delete(0, tk.END)

# Connect to Server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, SERVER_PORT))

# Ask for username
username = simpledialog.askstring("Username", "Enter your name:")

# GUI Setup
root = tk.Tk()
root.title("LAN Chat")

chat_area = scrolledtext.ScrolledText(root, width=50, height=20)
chat_area.pack()

message_entry = tk.Entry(root, width=40)
message_entry.pack(side=tk.LEFT)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.RIGHT)

# Start Receiving Messages
threading.Thread(target=receive_messages, daemon=True).start()

root.mainloop()
client_socket.close()
