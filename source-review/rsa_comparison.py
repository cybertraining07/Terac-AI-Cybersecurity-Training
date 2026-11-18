
from collections import Counter
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate a temporary RSA key pair for this demonstration
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

message = b"SECURITY TEST"

print("=== RSA-OAEP Demonstration ===")

# Encrypt the same message five times
ciphertexts = []

for i in range(5):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    ciphertexts.append(ciphertext)
    print(f"Encryption {i + 1}: {ciphertext.hex()[:40]}...")

print("\nUnique ciphertexts:", len(set(ciphertexts)))
print("Total encryptions:", len(ciphertexts))

# Decrypt one ciphertext to verify correctness
plaintext = private_key.decrypt(
    ciphertexts[0],
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Recovered plaintext:", plaintext.decode())
