import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Server settings
SERVER_IP = "0.0.0.0"  # Accept connections from any device in LAN
SERVER_PORT = 12345
clients = []

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

def handle_client(client_socket):
    """Handles communication with a client."""
    clients.append(client_socket)
    while True:
        try:
            encrypted_msg = client_socket.recv(1024)
            if not encrypted_msg:
                break
            message = decrypt_message(encrypted_msg)
            print(f"Received: {message}")
            broadcast(encrypted_msg, client_socket)
        except:
            clients.remove(client_socket)
            client_socket.close()
            break

def broadcast(message, sender_socket):
    """Sends a message to all clients except the sender."""
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                clients.remove(client)

def start_server():
    """Starts the server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server started on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"New connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
