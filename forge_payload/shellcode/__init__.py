"""Shellcode template engine — architecture-specific shellcode generators.

Each module exposes a class with methods for common payload types:
  reverse_tcp(), bind_tcp(), staged_tcp(), reverse_http(), exec_cmd()

Shellcode is returned as raw bytes ready for encoding and format wrapping.
Templates use PEB walking (Windows) and raw syscalls (Linux) to avoid
import table dependencies.
"""
