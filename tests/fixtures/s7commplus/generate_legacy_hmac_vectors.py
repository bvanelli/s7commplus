"""Regenerate public test vectors with OpenSSL, independently of library code.

Usage: python generate_legacy_hmac_vectors.py PATH_TO_LIBCRYPTO
Redirect stdout to legacy_fragment_hmac.json. Requires OpenSSL 1.1/3 with
SHA256_Init/Update/Final symbols. Not imported by the library or test suite.
"""

import ctypes
import json
import sys


class SHA256Context(ctypes.Structure):
    """SHA256_CTX from OpenSSL's public openssl/sha.h."""

    _fields_ = [
        ("h", ctypes.c_uint32 * 8),
        ("Nl", ctypes.c_uint32),
        ("Nh", ctypes.c_uint32),
        ("data", ctypes.c_uint32 * 16),
        ("num", ctypes.c_uint),
        ("md_len", ctypes.c_uint),
    ]


def generate(library_path: str) -> list[dict[str, int | str]]:
    lib = ctypes.CDLL(library_path)
    ctx_pointer = ctypes.POINTER(SHA256Context)
    lib.SHA256_Init.argtypes = [ctx_pointer]
    lib.SHA256_Update.argtypes = [ctx_pointer, ctypes.c_void_p, ctypes.c_size_t]
    lib.SHA256_Final.argtypes = [ctypes.c_void_p, ctx_pointer]
    for function in (lib.SHA256_Init, lib.SHA256_Update, lib.SHA256_Final):
        function.restype = ctypes.c_int

    def check(result: int) -> None:
        if result != 1:
            raise RuntimeError("OpenSSL SHA256 operation failed")

    key = bytes(range(24))  # Public synthetic test key, never a PLC session key.
    inner, outer = SHA256Context(), SHA256Context()
    for ctx, xor in ((inner, 0x36), (outer, 0x5C)):
        check(lib.SHA256_Init(ctypes.byref(ctx)))
        pad = bytes(value ^ xor for value in key.ljust(64, b"\0"))
        check(lib.SHA256_Update(ctypes.byref(ctx), pad, len(pad)))

    vectors: list[dict[str, int | str]] = []
    for size in (976, 976, 454, 55, 56, 63, 64, 65, 0):
        data = bytes((i * 13 + size) % 256 for i in range(size))
        check(lib.SHA256_Update(ctypes.byref(inner), data, len(data)))
        digest = ctypes.create_string_buffer(32)
        check(lib.SHA256_Final(digest, ctypes.byref(inner)))
        check(lib.SHA256_Update(ctypes.byref(outer), digest, 32))
        check(lib.SHA256_Final(digest, ctypes.byref(outer)))
        vectors.append({"size": size, "digest": digest.raw.hex()})
    return vectors


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: generate_legacy_hmac_vectors.py PATH_TO_LIBCRYPTO")
    print(json.dumps(generate(sys.argv[1]), indent=2))
