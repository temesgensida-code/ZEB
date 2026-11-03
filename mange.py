#!/usr/bin/env python
"""
Zero-crash safety stub for typo 'mange' -> 'manage'.
Redirects to Django's administrative entrypoint or production startup if runserver was requested on Render.
"""
import os
import sys
import warnings

warnings.warn(
    "Typo detected in start command ('mange' instead of 'manage'). "
    "Please update your Render Start Command to 'bash startup.sh'.",
    RuntimeWarning,
)

base_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(base_dir) != "backend":
    backend_dir = os.path.join(base_dir, "backend")
    if os.path.isdir(backend_dir):
        sys.path.insert(0, backend_dir)
        os.chdir(backend_dir)
else:
    backend_dir = base_dir

if __name__ == "__main__":
    if "runserver" in sys.argv and (os.environ.get("RENDER") or os.environ.get("PORT")):
        print(
            "Notice: 'runserver' detected in production environment. Forwarding to production startup script...",
            file=sys.stderr,
        )
        startup_script = os.path.join(backend_dir, "startup.sh")
        if os.path.exists(startup_script):
            os.execv("/bin/bash", ["bash", startup_script])

    from manage import main
    main()
