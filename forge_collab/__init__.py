"""ForgeCollab — Out-of-Band Testing Infrastructure.

Forge's equivalent of Burp Collaborator. Lightweight DNS + HTTP + SMTP
callback server for blind vulnerability confirmation.

Usage:
    python3 forge.py collab start --domain collab.example.com --port 53,80,25
"""
