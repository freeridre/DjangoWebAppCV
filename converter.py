from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64

# Your EC private key in PEM format
passkits_pem_private_key = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEID0VR/I814rQUqWIYPEhno+3kexN/jN2n1ub+mJ6ZWyhoAoGCCqGSM49
AwEHoUQDQgAEwKMBv29ByaSLiGF0FctuyB+Hs2oZ1kDIYhTVllPexNGudAlm8IWO
H0e+Exc97/zBdawu7Yl+XytQONszGzAK7w==
-----END EC PRIVATE KEY-----
"""
pem_private_key = """
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIQaBTu6q6k2xVp2hevp8zaEGdhCjIyU+HB8uQgd7SayoAoGCCqGSM49
AwEHoUQDQgAE0TZ/dq2KG9yrfBRXi3+mIAvRG6VnLjgAtgKahRuQGTO10gjD53g4
RPVp35yE3llqtvSjP95Xu89VoolDEtWDGg==
-----END EC PRIVATE KEY-----
"""

google_test_pem_private_key = """
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIJtF+UHZ7FlsOTZ4zL40dHiAiQoT7Ta8eUKAyRucHl9oAoGCCqGSM49
AwEHoUQDQgAEchyXj869zfmKhRi9xP7f2AK07kEo4lE7ZlWTN14jh4YBTny+hRGR
XcUzevV9zSSPJlPHpqqu5pEwlv1xyFvE1w==
-----END EC PRIVATE KEY-----
"""
# Load the private key from the PEM string
private_key = load_pem_private_key(
    pem_private_key.encode(),
    password=None,
    backend=default_backend()
)

# Extract the private key bytes
private_numbers = private_key.private_numbers()
private_key_bytes = private_numbers.private_value.to_bytes(32, byteorder='big')

# Convert to hexadecimal
hex_private_key = private_key_bytes.hex()

# Format with spaces (if required)
formatted_hex_private_key = ' '.join("0x" + hex_private_key[i:i+2]  for i in range(0, len(hex_private_key), 2))

print("Private Key (32-byte hex):", formatted_hex_private_key)