import csv
import os
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519, mlkem, mldsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESGCMSIV


def time_operation(writer, part, algorithm, operation, func, message_bytes=0, runs=101):
    """Run func() `runs` times, timing each run on its own, and write one row per run."""
    for run in range(runs):
        start = time.perf_counter_ns()
        func()
        end = time.perf_counter_ns()
        writer.writerow([part, algorithm, operation, message_bytes, run, end - start])


# ---------------------------------------------------------------- Part 1: key establishment

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)


def bench_rsa_oaep(writer, bits):
    name = f"RSA-OAEP-{bits}"
    print("Running", name)

    def keygen():
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    def encapsulate():
        secret = os.urandom(32)
        ciphertext = public_key.encrypt(secret, OAEP)
        return secret, ciphertext

    def decapsulate():
        return private_key.decrypt(ciphertext, OAEP)

    time_operation(writer, "kem", name, "keygen", keygen, runs=21)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "kem", name, "encapsulate", encapsulate)
    secret, ciphertext = encapsulate()
    time_operation(writer, "kem", name, "decapsulate", decapsulate)


def bench_ecdh(writer, name, curve):
    print("Running", name)

    def keygen():
        return ec.generate_private_key(curve)

    def encapsulate():
        ephemeral = ec.generate_private_key(curve)
        secret = ephemeral.exchange(ec.ECDH(), public_key)
        ciphertext = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return secret, ciphertext

    def decapsulate():
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(curve, ciphertext)
        return private_key.exchange(ec.ECDH(), ephemeral_public)

    time_operation(writer, "kem", name, "keygen", keygen)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "kem", name, "encapsulate", encapsulate)
    secret, ciphertext = encapsulate()
    time_operation(writer, "kem", name, "decapsulate", decapsulate)


def bench_x25519(writer):
    name = "X25519"
    print("Running", name)

    def keygen():
        return x25519.X25519PrivateKey.generate()

    def encapsulate():
        ephemeral = x25519.X25519PrivateKey.generate()
        secret = ephemeral.exchange(public_key)
        ciphertext = ephemeral.public_key().public_bytes_raw()
        return secret, ciphertext

    def decapsulate():
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        return private_key.exchange(ephemeral_public)

    time_operation(writer, "kem", name, "keygen", keygen)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "kem", name, "encapsulate", encapsulate)
    secret, ciphertext = encapsulate()
    time_operation(writer, "kem", name, "decapsulate", decapsulate)


def bench_mlkem(writer, name, key_class):
    print("Running", name)

    def keygen():
        return key_class.generate()

    def encapsulate():
        return public_key.encapsulate()          # returns (shared_secret, ciphertext)

    def decapsulate():
        return private_key.decapsulate(ciphertext)

    time_operation(writer, "kem", name, "keygen", keygen)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "kem", name, "encapsulate", encapsulate)
    secret, ciphertext = encapsulate()
    time_operation(writer, "kem", name, "decapsulate", decapsulate)


# ---------------------------------------------------------------- Part 2: digital signatures

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def bench_rsa_pss(writer, bits, message):
    name = f"RSA-PSS-{bits}"
    print("Running", name)

    def keygen():
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    def sign():
        return private_key.sign(message, PSS, hashes.SHA256())

    def verify():
        public_key.verify(signature, message, PSS, hashes.SHA256())

    time_operation(writer, "signature", name, "keygen", keygen, runs=21)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "signature", name, "sign", sign)
    signature = sign()
    time_operation(writer, "signature", name, "verify", verify)


def bench_ecdsa(writer, name, curve, hash_algorithm, message):
    print("Running", name)

    def keygen():
        return ec.generate_private_key(curve)

    def sign():
        return private_key.sign(message, ec.ECDSA(hash_algorithm))

    def verify():
        public_key.verify(signature, message, ec.ECDSA(hash_algorithm))

    time_operation(writer, "signature", name, "keygen", keygen)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "signature", name, "sign", sign)
    signature = sign()
    time_operation(writer, "signature", name, "verify", verify)


def bench_simple_signature(writer, name, key_class, message):
    """Ed25519 and ML-DSA: the message is passed directly to sign and verify."""
    print("Running", name)

    def keygen():
        return key_class.generate()

    def sign():
        return private_key.sign(message)

    def verify():
        public_key.verify(signature, message)

    time_operation(writer, "signature", name, "keygen", keygen)
    private_key = keygen()
    public_key = private_key.public_key()
    time_operation(writer, "signature", name, "sign", sign)
    signature = sign()
    time_operation(writer, "signature", name, "verify", verify)


# ---------------------------------------------------------------- Part 3: authenticated encryption

MESSAGE_LENGTHS = [64, 1024, 16384, 1048576]


def bench_aead(writer, name, cipher_class, key_bytes):
    for length in MESSAGE_LENGTHS:
        print("Running", name, length, "B")
        cipher = cipher_class(os.urandom(key_bytes))
        message = os.urandom(length)

        # encrypt: a fresh nonce every run, made BEFORE the clock starts
        for run in range(101):
            nonce = os.urandom(12)
            start = time.perf_counter_ns()
            cipher.encrypt(nonce, message, None)
            end = time.perf_counter_ns()
            writer.writerow(["aead", name, "encrypt", length, run, end - start])

        # decrypt: the same ciphertext every run
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, message, None)
        time_operation(writer, "aead", name, "decrypt",
                       lambda: cipher.decrypt(nonce, ciphertext, None),
                       message_bytes=length)


# ---------------------------------------------------------------- main

def main():
    out_dir = sys.argv[1]                      # e.g. results/run-1
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "raw.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["part", "algorithm", "operation",
                         "message_bytes", "run", "nanoseconds"])

        # Table 1: key establishment
        bench_rsa_oaep(writer, 3072)
        bench_rsa_oaep(writer, 7680)
        bench_ecdh(writer, "ECDH-P-256", ec.SECP256R1())
        bench_ecdh(writer, "ECDH-P-384", ec.SECP384R1())
        bench_ecdh(writer, "ECDH-P-521", ec.SECP521R1())
        bench_x25519(writer)
        bench_mlkem(writer, "ML-KEM-768", mlkem.MLKEM768PrivateKey)
        bench_mlkem(writer, "ML-KEM-1024", mlkem.MLKEM1024PrivateKey)

        # Table 2: digital signatures (one random 1 KiB message for everything)
        message = os.urandom(1024)
        bench_rsa_pss(writer, 3072, message)
        bench_rsa_pss(writer, 7680, message)
        bench_ecdsa(writer, "ECDSA-P-256", ec.SECP256R1(), hashes.SHA256(), message)
        bench_ecdsa(writer, "ECDSA-P-384", ec.SECP384R1(), hashes.SHA384(), message)
        bench_ecdsa(writer, "ECDSA-P-521", ec.SECP521R1(), hashes.SHA512(), message)
        bench_simple_signature(writer, "Ed25519", ed25519.Ed25519PrivateKey, message)
        bench_simple_signature(writer, "ML-DSA-44", mldsa.MLDSA44PrivateKey, message)
        bench_simple_signature(writer, "ML-DSA-65", mldsa.MLDSA65PrivateKey, message)
        bench_simple_signature(writer, "ML-DSA-87", mldsa.MLDSA87PrivateKey, message)

        # Table 3: authenticated encryption
        bench_aead(writer, "AES-128-GCM", AESGCM, 16)
        bench_aead(writer, "AES-256-GCM", AESGCM, 32)
        bench_aead(writer, "ChaCha20-Poly1305", ChaCha20Poly1305, 32)
        bench_aead(writer, "AES-256-GCM-SIV", AESGCMSIV, 32)

    print("Done. Wrote", path)


if __name__ == "__main__":
    main()
