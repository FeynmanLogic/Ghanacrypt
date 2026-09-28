#!/usr/bin/env python3
"""Keyed Ghana-patha-inspired encoding protected with RSA-OAEP.

This is a research prototype, not a production cryptosystem.

Each 128-byte plaintext block is placed in a key-derived permutation and
traversed as Forward | Reverse | Forward. The three observations permit
majority repair of one damaged observation per position. HMAC authenticates
the recovered block. A 4096-bit RSA key is required because the resulting
445-byte record is one byte below the OAEP-SHA256 limit of 446 bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


BLOCK_SIZE = 128
TRAVERSAL_SIZE = BLOCK_SIZE * 3
NONCE_SIZE = 16
TAG_SIZE = 32
RSA_BITS = 4096
RSA_BYTES = RSA_BITS // 8
OAEP_LIMIT = RSA_BYTES - 2 * hashes.SHA256().digest_size - 2

RECORD_MAGIC = b"GHP2"
MESSAGE_MAGIC = b"GHRS2"
HEADER = struct.Struct(">4s16sIIB")  # magic, nonce, index, total, data length
MESSAGE_HEADER = struct.Struct(">5sI")
RECORD_SIZE = HEADER.size + TRAVERSAL_SIZE + TAG_SIZE

assert RECORD_SIZE == 445
assert OAEP_LIMIT == 446


class GhanaError(ValueError):
    """Base error for malformed, corrupted, or incorrectly keyed records."""


@dataclass(frozen=True)
class DecodedBlock:
    index: int
    total: int
    data: bytes
    corrected_positions: int


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=b"keyed-ghana-rsa-v2",
    )


def _derive(master_key: bytes, purpose: bytes, nonce: bytes, index: int) -> bytes:
    if len(master_key) < 32:
        raise ValueError("Ghana master key must contain at least 32 random bytes")
    return hmac.new(
        master_key,
        purpose + b"\0" + nonce + struct.pack(">I", index),
        hashlib.sha256,
    ).digest()


class _HmacRandom:
    """Deterministic HMAC-based byte stream for the Fisher-Yates shuffle."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0
        self.buffer = bytearray()

    def read(self, count: int) -> bytes:
        while len(self.buffer) < count:
            self.buffer.extend(
                hmac.new(
                    self.seed,
                    b"shuffle" + struct.pack(">Q", self.counter),
                    hashlib.sha256,
                ).digest()
            )
            self.counter += 1
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def below(self, upper: int) -> int:
        """Uniform integer in range(upper), using rejection sampling."""
        if not 1 <= upper <= 256:
            raise ValueError("upper must be between 1 and 256")
        cutoff = 256 - (256 % upper)
        while True:
            candidate = self.read(1)[0]
            if candidate < cutoff:
                return candidate % upper


def keyed_permutation(master_key: bytes, nonce: bytes, index: int) -> list[int]:
    seed = _derive(master_key, b"permutation", nonce, index)
    random_stream = _HmacRandom(seed)
    order = list(range(BLOCK_SIZE))
    for position in range(BLOCK_SIZE - 1, 0, -1):
        swap = random_stream.below(position + 1)
        order[position], order[swap] = order[swap], order[position]
    return order


def _tag(master_key: bytes, header: bytes, padded_plaintext: bytes) -> bytes:
    auth_key = hmac.new(master_key, b"ghana-authentication-v2", hashlib.sha256).digest()
    return hmac.new(auth_key, header + padded_plaintext, hashlib.sha256).digest()


def encode_block(
    data: bytes, master_key: bytes, nonce: bytes, index: int, total: int
) -> bytes:
    if not 0 <= len(data) <= BLOCK_SIZE:
        raise ValueError("a plaintext block can contain at most 128 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must contain exactly 16 bytes")

    padded = data.ljust(BLOCK_SIZE, b"\0")
    order = keyed_permutation(master_key, nonce, index)
    forward = bytes(padded[position] for position in order)
    traversal = forward + forward[::-1] + forward
    header = HEADER.pack(RECORD_MAGIC, nonce, index, total, len(data))
    return header + traversal + _tag(master_key, header, padded)


def decode_block(record: bytes, master_key: bytes) -> DecodedBlock:
    if len(record) != RECORD_SIZE:
        raise GhanaError(f"record must contain exactly {RECORD_SIZE} bytes")

    header = record[: HEADER.size]
    magic, nonce, index, total, data_length = HEADER.unpack(header)
    if magic != RECORD_MAGIC or total == 0 or index >= total or data_length > BLOCK_SIZE:
        raise GhanaError("invalid Ghana record header")

    traversal = record[HEADER.size : HEADER.size + TRAVERSAL_SIZE]
    supplied_tag = record[-TAG_SIZE:]
    first = traversal[:BLOCK_SIZE]
    second = traversal[BLOCK_SIZE : 2 * BLOCK_SIZE][::-1]
    third = traversal[2 * BLOCK_SIZE :]

    corrected = 0
    recovered_forward = bytearray(BLOCK_SIZE)
    for position, observations in enumerate(zip(first, second, third)):
        a, b, c = observations
        if a == b or a == c:
            recovered_forward[position] = a
        elif b == c:
            recovered_forward[position] = b
        else:
            raise GhanaError(
                f"block {index}: all three observations differ at traversal position {position}"
            )
        corrected += int(not (a == b == c))

    order = keyed_permutation(master_key, nonce, index)
    padded = bytearray(BLOCK_SIZE)
    for traversal_position, original_position in enumerate(order):
        padded[original_position] = recovered_forward[traversal_position]

    expected_tag = _tag(master_key, header, bytes(padded))
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise GhanaError(f"block {index}: authentication failed (wrong key or corruption)")

    return DecodedBlock(index, total, bytes(padded[:data_length]), corrected)


def encrypt(public_key: rsa.RSAPublicKey, master_key: bytes, plaintext: bytes) -> bytes:
    if public_key.key_size != RSA_BITS:
        raise ValueError("this format requires a 4096-bit RSA public key")

    nonce = os.urandom(NONCE_SIZE)
    chunks = [plaintext[i : i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    encrypted = [
        public_key.encrypt(encode_block(chunk, master_key, nonce, index, total), _oaep())
        for index, chunk in enumerate(chunks)
    ]
    return MESSAGE_HEADER.pack(MESSAGE_MAGIC, total) + b"".join(encrypted)


def decrypt(
    private_key: rsa.RSAPrivateKey, master_key: bytes, ciphertext: bytes
) -> tuple[bytes, int]:
    if private_key.key_size != RSA_BITS:
        raise ValueError("this format requires a 4096-bit RSA private key")
    if len(ciphertext) < MESSAGE_HEADER.size:
        raise GhanaError("ciphertext is too short")

    magic, declared_total = MESSAGE_HEADER.unpack(ciphertext[: MESSAGE_HEADER.size])
    body = ciphertext[MESSAGE_HEADER.size :]
    if magic != MESSAGE_MAGIC or declared_total == 0:
        raise GhanaError("invalid encrypted-message header")
    if len(body) != declared_total * RSA_BYTES:
        raise GhanaError("missing, extra, or truncated RSA block")

    decoded: dict[int, DecodedBlock] = {}
    message_nonce: bytes | None = None
    correction_count = 0
    for physical_index in range(declared_total):
        rsa_block = body[physical_index * RSA_BYTES : (physical_index + 1) * RSA_BYTES]
        try:
            record = private_key.decrypt(rsa_block, _oaep())
        except ValueError as exc:
            raise GhanaError(f"RSA-OAEP rejected ciphertext block {physical_index}") from exc

        block = decode_block(record, master_key)
        _, nonce, _, _, _ = HEADER.unpack(record[: HEADER.size])
        if message_nonce is None:
            message_nonce = nonce
        elif nonce != message_nonce:
            raise GhanaError("records from different messages were mixed")
        if block.total != declared_total or block.index in decoded:
            raise GhanaError("duplicate block or inconsistent total-block count")
        decoded[block.index] = block
        correction_count += block.corrected_positions

    expected_indices = set(range(declared_total))
    if set(decoded) != expected_indices:
        raise GhanaError("one or more logical blocks are missing")
    return b"".join(decoded[i].data for i in range(declared_total)), correction_count


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def self_test() -> None:
    private_key = generate_rsa_key()
    public_key = private_key.public_key()
    ghana_key = os.urandom(32)

    cases = [b"", b"abc", os.urandom(127), os.urandom(128), os.urandom(129), os.urandom(500)]
    for original in cases:
        ciphertext = encrypt(public_key, ghana_key, original)
        recovered, corrections = decrypt(private_key, ghana_key, ciphertext)
        assert recovered == original and corrections == 0

    # A wrong Ghana key is rejected after successful RSA decryption.
    try:
        decrypt(private_key, os.urandom(32), encrypt(public_key, ghana_key, b"secret"))
    except GhanaError:
        pass
    else:
        raise AssertionError("wrong Ghana key was accepted")

    # A damaged RSA ciphertext block is rejected by OAEP.
    damaged = bytearray(encrypt(public_key, ghana_key, b"RSA corruption"))
    damaged[-1] ^= 1
    try:
        decrypt(private_key, ghana_key, bytes(damaged))
    except GhanaError:
        pass
    else:
        raise AssertionError("damaged RSA ciphertext was accepted")

    # Test the Ghana layer directly: one of three copies can be repaired.
    nonce = os.urandom(NONCE_SIZE)
    record = bytearray(encode_block(b"single-copy repair", ghana_key, nonce, 0, 1))
    record[HEADER.size + 10] ^= 1
    decoded = decode_block(bytes(record), ghana_key)
    assert decoded.data == b"single-copy repair" and decoded.corrected_positions == 1

    # Encrypted records can be delivered out of order; authenticated indices
    # restore their logical order after independent RSA decryption.
    ordered_plaintext = os.urandom(300)
    ordered_ciphertext = encrypt(public_key, ghana_key, ordered_plaintext)
    envelope = ordered_ciphertext[: MESSAGE_HEADER.size]
    rsa_blocks = [
        ordered_ciphertext[i : i + RSA_BYTES]
        for i in range(MESSAGE_HEADER.size, len(ordered_ciphertext), RSA_BYTES)
    ]
    rsa_blocks[0], rsa_blocks[-1] = rsa_blocks[-1], rsa_blocks[0]
    recovered, _ = decrypt(private_key, ghana_key, envelope + b"".join(rsa_blocks))
    assert recovered == ordered_plaintext

    print(
        f"Passed {len(cases)} round trips, wrong-key rejection, RSA tamper rejection, "
        "Ghana repair, and block reordering."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", nargs="?", default="agnim ile purohitam")
    parser.add_argument("--skip-tests", action="store_true", help="skip the built-in test suite")
    args = parser.parse_args()

    if not args.skip_tests:
        self_test()

    private_key = generate_rsa_key()
    ghana_key = os.urandom(32)
    plaintext = args.message.encode("utf-8")
    ciphertext = encrypt(private_key.public_key(), ghana_key, plaintext)
    recovered, corrections = decrypt(private_key, ghana_key, ciphertext)

    print(f"Plaintext bytes:  {len(plaintext)}")
    print(f"Ciphertext bytes: {len(ciphertext)}")
    print(f"Ghana key:        {ghana_key.hex()}  (demo only; normally store securely)")
    print(f"Corrected bytes:  {corrections}")
    print(f"Recovered:        {recovered.decode('utf-8')}")


if __name__ == "__main__":
    main()
