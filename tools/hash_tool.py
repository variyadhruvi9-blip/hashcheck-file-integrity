# =============================================================================
# tools/hash_tool.py — Hash & Integrity Checker logic
#
# Hashes a file-like object in fixed-size chunks so the entire file is never
# loaded into memory at once.  This matters for large files: reading 64 KB at
# a time keeps peak memory usage constant regardless of file size.
#
# Why MD5 and SHA-1 are considered weak
# ──────────────────────────────────────
# A hash function is "broken" when an attacker can deliberately produce two
# different inputs that share the same digest (a "collision").
#
# MD5  — Collision attacks have been practical since 2004.  Researchers and
#         malware authors have created pairs of files with identical MD5 hashes.
#         It MUST NOT be used for security purposes.
#
# SHA-1 — Fully broken in 2017 by the SHAttered attack (shattered.io), which
#         produced two real PDF files with the same SHA-1 digest for less than
#         USD 100 000 in cloud compute.  Browsers and CAs stopped accepting
#         SHA-1 certificates years ago.
#
# SHA-256 — Part of the SHA-2 family.  No collision attack is known; the
#            256-bit digest space makes brute-force search computationally
#            infeasible.  It is the current standard for file integrity and
#            digital signatures.
#
# Even MD5/SHA-1 still detect *accidental* corruption (bit-rot, bad downloads)
# reliably — collisions require deliberate crafting.  Use SHA-256 whenever
# security against a motivated attacker matters.
# =============================================================================

import hashlib

# Read the file in 64 KB chunks — small enough to keep memory flat, large
# enough that the number of read() calls stays low even for big files.
_CHUNK_SIZE = 64 * 1024  # 64 KB


def compute_hashes(file_stream):
    """
    Read *file_stream* in chunks and return a dict with keys
    'md5', 'sha1', and 'sha256', each mapped to a lowercase hex digest.

    *file_stream* must be a readable binary file-like object (e.g. a Flask
    FileStorage stream).  The caller is responsible for closing it.
    """
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    while chunk := file_stream.read(_CHUNK_SIZE):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
