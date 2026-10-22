# =============================================================================
# app.py — HashCheck: File Integrity Verifier entry point
#
# This file creates the Flask app, applies security settings, and registers
# all the URL routes (pages) for the site.
# =============================================================================

from flask import Flask, render_template, redirect, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from tools.hash_tool import compute_hashes

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------

# Flask(__name__) tells Flask to look for templates/ and static/ folders
# relative to THIS file's location.
app = Flask(__name__)

# --- Security settings -------------------------------------------------------

# Limit uploaded files to 16 MB. Flask will automatically return a 413 error
# (Request Entity Too Large) if a file exceeds this size.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB in bytes

# A secret key is required by Flask for session security.
# In a real project you would load this from an environment variable.
# For local development a hard-coded string is acceptable.
app.config["SECRET_KEY"] = "hashcheck-dev-key-change-in-production"

# IMPORTANT: Never run with debug=True in production — it exposes your source
# code and allows arbitrary code execution on the server.
# We default to debug=False here and only override it in __main__.

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _human_size(n_bytes):
    """Return a human-readable file size string (e.g. '1.23 MB')."""
    for unit in ("B", "KB", "MB"):
        if n_bytes < 1024:
            return f"{n_bytes:.0f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.2f} GB"


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.route("/")
def index():
    """Root — redirect straight to the hash tool (the only tool)."""
    return redirect(url_for("hash_tool"))


@app.route("/hash", methods=["GET", "POST"])
def hash_tool():
    """
    Hash & Integrity Checker.

    GET  — renders the empty upload form.
    POST — reads the uploaded file entirely in memory via chunked hashing
           (never written to disk), computes MD5 / SHA-1 / SHA-256, and
           re-renders the page with the results.
    """
    if request.method == "GET":
        return render_template("hash_tool.html")

    # ── POST: process the uploaded file ──────────────────────────────────────

    uploaded = request.files.get("file")
    # Normalise the expected hash: lowercase, strip all whitespace (including
    # internal spaces so "a3 f1 …" pasted from a download page still matches).
    expected = "".join(request.form.get("expected", "").split()).lower()

    # Validate that a file was actually attached and has a name.
    if not uploaded or not uploaded.filename:
        return render_template(
            "hash_tool.html",
            error="No file was selected. Please choose a file and try again.",
            expected=expected,
        )

    # Compute all three digests by streaming the file in chunks.
    # FileStorage.stream is the raw binary stream; it is never saved to disk.
    hashes = compute_hashes(uploaded.stream)

    # Determine the file size.  After compute_hashes() the stream pointer is
    # at the end, so seek to end then read tell().
    uploaded.stream.seek(0, 2)
    n_bytes = uploaded.stream.tell()
    file_size = _human_size(n_bytes)

    # Friendly error for empty files — hashing succeeds but the result is
    # meaningless and would confuse the user.
    if n_bytes == 0:
        return render_template(
            "hash_tool.html",
            error=(
                f'"{uploaded.filename}" appears to be empty (0 bytes). '
                "Please choose a file that contains data."
            ),
            expected=expected,
        )

    # ── Optional expected-hash comparison ────────────────────────────────────
    match_status = None
    match_algo   = None

    if expected:
        # Normalise: lowercase, strip whitespace.  Compare against each digest.
        # We report which algorithm the provided hash length matches so the
        # user knows what they compared against.
        algo_map = {
            32:  ("md5",    "MD5"),
            40:  ("sha1",   "SHA-1"),
            64:  ("sha256", "SHA-256"),
        }
        algo_key, algo_label = algo_map.get(len(expected), (None, "unknown"))

        if algo_key and hashes[algo_key] == expected:
            match_status = "MATCH"
            match_algo   = algo_label
        else:
            match_status = "MISMATCH"
            # If the length matched a known algorithm, name it; otherwise leave
            # it generic so the user knows no algorithm matched.
            match_algo = algo_label if algo_key else "any algorithm"

    return render_template(
        "hash_tool.html",
        filename=uploaded.filename,
        file_size=file_size,
        results=hashes,
        expected=expected,
        match_status=match_status,
        match_algo=match_algo,
    )


# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(e):
    """Return a friendly page when the upload exceeds MAX_CONTENT_LENGTH."""
    return render_template(
        "hash_tool.html",
        error="The uploaded file exceeds the 16 MB limit. Please choose a smaller file.",
    ), 413


# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
