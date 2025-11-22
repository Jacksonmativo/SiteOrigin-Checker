"""Top-level WSGI entrypoint for deployments.

Some PaaS providers (e.g. Render) run Gunicorn from a working directory
where the `backend` package is not automatically importable as a top-level
module. Providing this small adapter at the repository root lets you keep
the package layout and use the simpler `gunicorn app:app` invocation.
"""
try:
    # Normal case when repository root is on PYTHONPATH
    from backend.app import app
except Exception:
    # Fallback: attempt importing relative to current module location
    # (useful for local editing contexts)
    import importlib
    import os
    import sys
    repo_root = os.path.dirname(__file__)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    backend_app = importlib.import_module('backend.app')
    app = getattr(backend_app, 'app')
