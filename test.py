from cryptography.hazmat.primitives.ciphers import algorithms

SECRET_KEY = b"thisisaverysecur"  # Replace with your key

print(f"Key Length: {len(SECRET_KEY)} bytes")

try:
    cipher = algorithms.AES(SECRET_KEY)
    print("✅ Key is valid for AES!")
except ValueError as e:
    print(f"❌ Error: {e}")
