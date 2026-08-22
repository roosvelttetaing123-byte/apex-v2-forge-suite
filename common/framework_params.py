"""
Framework parameter blacklist — params that should NEVER be injection-tested.

These are framework-internal fields (ASP.NET ViewState, CSRF tokens, etc.)
that produce false positives when fuzzed because:
  1. They're not user-controlled inputs
  2. Tampering them causes generic server errors (not vuln indicators)
  3. They contain encoded/encrypted blobs, not injectable text
"""

# ASP.NET
_ASPNET = {
    "__VIEWSTATE", "__VIEWSTATEGENERATOR", "__VIEWSTATEENCRYPTED",
    "__EVENTVALIDATION", "__EVENTTARGET", "__EVENTARGUMENT",
    "__PREVIOUSPAGE", "__SCROLLPOSITIONX", "__SCROLLPOSITIONY",
    "__ASYNCPOST",
}

# CSRF tokens (various frameworks)
_CSRF = {
    "csrfmiddlewaretoken",   # Django
    "_token",                # Laravel
    "authenticity_token",    # Rails
    "_csrf",                 # Express/CSRF
    "__RequestVerificationToken",  # ASP.NET MVC
    "csrf_token",            # Generic
    "XSRF-TOKEN",            # Angular
}

# Java/Spring
_JAVA = {
    "javax.faces.ViewState",
    "_flowExecutionKey",
    "JSESSIONID",
}

# All framework params combined
FRAMEWORK_PARAMS: frozenset[str] = frozenset(
    _ASPNET | _CSRF | _JAVA
)


def is_framework_param(param_name: str) -> bool:
    """Check if a parameter is a framework-internal field that should be skipped.
    
    Case-insensitive check against known framework params.
    """
    return param_name in FRAMEWORK_PARAMS or param_name.lower() in {
        p.lower() for p in FRAMEWORK_PARAMS
    }
"""Module for framework parameter blacklisting."""
