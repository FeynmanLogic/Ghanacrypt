# Keyed Ghana RSA

This project explores whether the forward and reverse structure of Vedic Ghana Krama recitation can be adapted into a keyed data transformation layered on RSA.

Instead of processing positions only as `1-2-3`, Ghana-inspired traversal revisits them in patterns such as `12-21-123-321-123`. In this prototype, plaintext is divided into 128-byte blocks. A secret key generates a different permutation for each block, which is traversed forward, backward, and forward before RSA encryption.

## Features

- 128-byte plaintext blocks
- Key-derived position permutation
- Forward-reverse-forward traversal
- Three-copy majority error correction
- HMAC-SHA256 block authentication
- Block reordering and corruption detection
- 4096-bit RSA-OAEP with SHA-256
- No AES dependency

## Install and run

```bash
pip install cryptography
python3 keyed_ghana_rsa.py "Your secret message"
```

The script runs its built-in tests, generates temporary RSA and Ghana keys, encrypts the supplied message, decrypts it, and verifies the result.

To skip the tests:

```bash
python3 keyed_ghana_rsa.py "Your secret message" --skip-tests
```

## Security note

This is an experimental research prototype, not a production cryptosystem. Its established public-key security comes from RSA-OAEP. The Ghana layer adds keyed permutation, redundancy, error localization, and limited correction, but it has not been independently proven to make RSA harder to break.
