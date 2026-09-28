# Keyed Ghana RSA

This project begins exploring whether the forward and reverse structure of Vedic Ghana Krama recitation can inspire a new family of keyed data transformations layered on established cryptography such as RSA.

Instead of processing positions only as `1-2-3`, Ghana-inspired traversal revisits them in patterns such as `12-21-123-321-123`. In this first prototype, plaintext is divided into 128-byte blocks. A secret key generates a different permutation for each block, which is traversed forward, backward, and forward before RSA encryption.

The longer-term idea is to study whether richer Ghana-inspired traversal families can provide useful redundancy, synchronization, tamper localization, or resistance to burst errors. Future versions could explore variable traversal depths, independently rotated passes, alternative block sizes, and formal comparisons with repetition codes, interleaving, and modern error-correcting codes.

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

This is an experimental research prototype, not a production cryptosystem. Its established public-key security currently comes from RSA-OAEP. The Ghana layer adds keyed permutation, redundancy, error localization, and limited correction, but it has not been independently proven to make RSA harder to break.

The purpose of the project is not to claim immediate cryptographic superiority. It is to turn a historical method of preserving ordered information into a testable computational idea, measure where it helps, identify where it does not, and explore whether the structure can lead to useful future encoding or security mechanisms.
