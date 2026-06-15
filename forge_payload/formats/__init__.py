"""Format builders — wrap encoded shellcode in a deployable container.

Each builder returns raw bytes in the chosen format:
  PE  → C source for Windows EXE (compile with MinGW)
  ELF → C source for Linux ELF (compile with GCC)
  DLL → C source for Windows DLL
  PS1 → PowerShell script (no compile needed, in-memory exec)
  HTA → HTA/VBA dropper (MS Office or MSHTA delivery)
"""
