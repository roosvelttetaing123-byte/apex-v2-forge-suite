"""Stager builders — small first-stage payloads that download and execute a larger stage.

HTTP stager: Pull stage from http(s)://lhost:lport/stage
DNS stager:  Pull stage encoded in DNS TXT records
SMB stager:  Read stage from an SMB named pipe

All stagers return (script_bytes, oneliner_str) tuples.
"""
