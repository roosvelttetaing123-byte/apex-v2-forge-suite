"""Payload encoders — obfuscate shellcode to bypass signature detection.

Each encoder returns (encoded_bytes, metadata) and generates a self-contained
decoder stub that can be prepended to the payload for in-memory decoding.
"""
