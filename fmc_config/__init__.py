# Prefer local override if present; otherwise use the committed default.
try:
    from .config_local import BASE_URL
except Exception:
    from .config_default import BASE_URL
