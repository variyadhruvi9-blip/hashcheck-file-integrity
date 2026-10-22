# =============================================================================
# VariyaDhruvi_HashCheck.py — HashCheck: File Integrity Verifier
#
# A self-contained single-file Flask application.
# All logic, routes, CSS, and HTML are in this one file.
#
# Run with:
#   python VariyaDhruvi_HashCheck.py
# Then open:
#   http://127.0.0.1:5000
#
# Dependencies: Flask (pip install flask)
# Standard library: hashlib
# Author: Variya Dhruvi
# Course: MSc Cybersecurity
# =============================================================================

import hashlib
from flask import Flask, redirect, request, url_for, render_template_string
from werkzeug.exceptions import RequestEntityTooLarge

# =============================================================================
# App setup
# =============================================================================

app = Flask(__name__)

# Limit uploads to 16 MB. Flask raises RequestEntityTooLarge automatically
# if a file exceeds this before the route handler even runs.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

# Required by Flask for session security.
# In production, load this from an environment variable.
app.config["SECRET_KEY"] = "hashcheck-dev-key-change-in-production"

# =============================================================================
# Hashing logic
# =============================================================================

# Read the file in 64 KB chunks — keeps memory usage flat for large files.
_CHUNK_SIZE = 64 * 1024  # 64 KB


def compute_hashes(file_stream):
    """
    Read *file_stream* in 64 KB chunks and return a dict:
        { 'md5': '...', 'sha1': '...', 'sha256': '...' }
    All three digests are computed in a single pass.
    *file_stream* must be a readable binary file-like object.
    """
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    while chunk := file_stream.read(_CHUNK_SIZE):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# =============================================================================
# Helpers
# =============================================================================

def _human_size(n_bytes):
    """Return a human-readable file size string (e.g. '1.23 MB')."""
    for unit in ("B", "KB", "MB"):
        if n_bytes < 1024:
            return f"{n_bytes:.0f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.2f} GB"


# =============================================================================
# HTML template (inline — replaces templates/base.html + templates/hash_tool.html)
# =============================================================================

# render_template_string() renders this string exactly like a Jinja2 file.
# Jinja2 auto-escapes all {{ variables }} in HTML templates, preventing XSS.

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>HashCheck: File Integrity Verifier</title>
  <style>
    /* ── Reset & base ──────────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
      font-size: 15px;
      line-height: 1.6;
      background-color: #f0f2f5;
      color: #1f2328;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* ── Layout ────────────────────────────────────────────────────────── */
    .container {
      width: 100%;
      max-width: 960px;
      margin: 0 auto;
      padding: 2rem 1rem;
      flex: 1;
    }

    /* ── Navbar ────────────────────────────────────────────────────────── */
    .navbar {
      background-color: #1f2328;
      padding: 0.9rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .nav-brand {
      color: #ffffff;
      font-size: 1.2rem;
      font-weight: 700;
      text-decoration: none;
      letter-spacing: 0.5px;
    }
    .nav-links { list-style: none; display: flex; gap: 1.5rem; }
    .nav-links a { color: #c9d1d9; text-decoration: none; font-size: 0.95rem; transition: color 0.2s; }
    .nav-links a:hover { color: #ffffff; }

    /* ── Hero ──────────────────────────────────────────────────────────── */
    .hero { text-align: center; padding: 2.5rem 1rem 2rem; }
    .hero h1 { font-size: 2rem; font-weight: 700; margin-bottom: 0.6rem; }
    .hero-sub { font-size: 1.05rem; color: #57606a; max-width: 560px; margin: 0 auto; }
    .hero--tool { padding-bottom: 0.5rem; }

    /* ── Tool section card ─────────────────────────────────────────────── */
    .tool-section {
      background-color: #ffffff;
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      padding: 1.75rem;
      margin-bottom: 1.5rem;
    }

    /* ── Upload form ───────────────────────────────────────────────────── */
    .hash-form { display: flex; flex-direction: column; gap: 1.25rem; }
    .form-group { display: flex; flex-direction: column; gap: 0.35rem; }
    .form-label { font-weight: 600; font-size: 0.95rem; display: flex; flex-direction: column; gap: 0.15rem; }
    .form-hint { font-weight: 400; font-size: 0.82rem; color: #57606a; }
    .input-file {
      border: 1px solid #d0d7de; border-radius: 6px;
      padding: 0.45rem 0.6rem; font-size: 0.9rem;
      background-color: #f7f8fa; cursor: pointer; width: 100%;
    }
    .input-file:focus { outline: 2px solid #3b82d4; outline-offset: 1px; }
    .input-text {
      border: 1px solid #d0d7de; border-radius: 6px;
      padding: 0.5rem 0.75rem; font-size: 0.875rem;
      font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
      width: 100%; background-color: #f7f8fa; color: #1f2328;
    }
    .input-text:focus { outline: 2px solid #3b82d4; outline-offset: 1px; background-color: #fff; }

    /* ── Buttons ───────────────────────────────────────────────────────── */
    .btn {
      display: inline-block; padding: 0.5rem 1rem; border-radius: 6px;
      font-size: 0.875rem; font-weight: 600; text-decoration: none;
      text-align: center; cursor: pointer; border: none;
    }
    .btn-primary { background-color: #3b82d4; color: #ffffff; }
    .btn-primary:hover { background-color: #2f6bbf; }
    .btn-lg { padding: 0.65rem 1.5rem; font-size: 0.95rem; align-self: flex-start; }

    /* ── Alerts ────────────────────────────────────────────────────────── */
    .alert {
      border-radius: 8px; padding: 0.85rem 1.1rem; font-size: 0.9rem;
      margin-bottom: 1.25rem; border-left: 4px solid transparent;
    }
    .alert--error   { background-color: #fff5f5; border-left-color: #e53e3e; color: #742a2a; }
    .alert--match   { background-color: #f0fff4; border-left-color: #38a169; color: #1c4532; font-size: 0.95rem; }
    .alert--mismatch{ background-color: #fff5f5; border-left-color: #e53e3e; color: #742a2a; font-size: 0.95rem; }

    /* ── Result metadata ───────────────────────────────────────────────── */
    .result-meta { display: flex; align-items: baseline; gap: 0.75rem; margin-bottom: 1rem; }
    .result-filename { font-weight: 600; font-size: 0.95rem; word-break: break-all; }
    .result-size { font-size: 0.82rem; color: #57606a; white-space: nowrap; }

    /* ── Hash digest table ─────────────────────────────────────────────── */
    .hash-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .hash-table thead th {
      text-align: left; padding: 0.5rem 0.75rem;
      border-bottom: 2px solid #e5e7eb; color: #57606a;
      font-weight: 600; white-space: nowrap;
    }
    .hash-table tbody td { padding: 0.65rem 0.75rem; border-bottom: 1px solid #f0f2f5; vertical-align: middle; }
    .algo-name  { font-weight: 700; white-space: nowrap; width: 7rem; }
    .digest     { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 0.8rem; word-break: break-all; }
    .digest code{ background: none; color: #1f2328; }
    .algo-note  { color: #57606a; font-size: 0.82rem; white-space: nowrap; }
    .hash-row--weak   { background-color: #fffbf0; }
    .hash-row--strong { background-color: #f0fff4; }

    /* ── Copy button ───────────────────────────────────────────────────── */
    .copy-btn {
      display: inline-block; margin-left: 0.5rem;
      padding: 0.15rem 0.45rem; font-size: 0.75rem;
      border: 1px solid #d0d7de; border-radius: 4px;
      background: #f7f8fa; color: #57606a;
      cursor: pointer; vertical-align: middle; white-space: nowrap;
    }
    .copy-btn:hover { background: #e5e7eb; color: #1f2328; }

    /* ── Explainer panel ───────────────────────────────────────────────── */
    .explainer h2 { font-size: 1rem; font-weight: 700; margin-bottom: 0.5rem; margin-top: 1.25rem; }
    .explainer h2:first-child { margin-top: 0; }
    .explainer p, .explainer ul { font-size: 0.9rem; color: #444c56; margin-bottom: 0.75rem; }
    .explainer ul { padding-left: 1.4rem; }
    .explainer li { margin-bottom: 0.4rem; }
    .explainer-note { font-size: 0.82rem; color: #57606a; font-style: italic; }

    /* ── Footer ────────────────────────────────────────────────────────── */
    .footer {
      text-align: center; padding: 1rem; font-size: 0.8rem;
      color: #57606a; border-top: 1px solid #e5e7eb; background-color: #ffffff;
    }

    /* ── Responsive: hide Notes column on small screens ────────────────── */
    @media (max-width: 640px) {
      .hash-table thead th:last-child,
      .hash-table tbody td:last-child,
      .algo-note { display: none; }
      .digest { font-size: 0.72rem; }
    }
  </style>
</head>
<body>

  <!-- Navbar -->
  <nav class="navbar">
    <a href="/" class="nav-brand">🔍 HashCheck</a>
    <ul class="nav-links">
      <li><a href="/hash">File Integrity Verifier</a></li>
    </ul>
  </nav>

  <!-- Page content -->
  <main class="container">

    <!-- Hero -->
    <section class="hero hero--tool">
      <h1>🔍 HashCheck: File Integrity Verifier</h1>
      <p class="hero-sub">
        Upload a file to compute its <strong>MD5</strong>, <strong>SHA-1</strong>,
        and <strong>SHA-256</strong> fingerprints. Optionally paste an expected hash
        to verify the file hasn't been altered.
      </p>
    </section>

    <!-- Upload form -->
    <section class="tool-section">
      <form method="POST" action="/hash" enctype="multipart/form-data" class="hash-form">

        <!-- File picker -->
        <div class="form-group">
          <label for="file" class="form-label">
            File to hash
            <span class="form-hint">Max 16 MB — the file is never saved to disk</span>
          </label>
          <input type="file" id="file" name="file" class="input-file" required />
        </div>

        <!-- Optional expected hash -->
        <div class="form-group">
          <label for="expected" class="form-label">
            Expected hash
            <span class="form-hint">Optional — paste a known hash to check if the file matches</span>
          </label>
          <input
            type="text" id="expected" name="expected" class="input-text"
            placeholder="e.g. a3f1… (MD5, SHA-1, or SHA-256)"
            spellcheck="false" autocomplete="off"
            value="{{ expected | default('') }}"
          />
        </div>

        <button type="submit" class="btn btn-primary btn-lg">Compute Hashes</button>
      </form>
    </section>

    <!-- Error banner (shown only when an error occurred) -->
    {% if error %}
    <section class="tool-section">
      <div class="alert alert--error">
        <strong>Error:</strong> {{ error }}
      </div>
    </section>
    {% endif %}

    <!-- Results (shown only after a successful POST) -->
    {% if results %}
    <section class="tool-section">

      <!-- File name and size -->
      <div class="result-meta">
        <span class="result-filename">{{ filename }}</span>
        <span class="result-size">{{ file_size }}</span>
      </div>

      <!-- MATCH / MISMATCH badge -->
      {% if match_status == "MATCH" %}
      <div class="alert alert--match">
        ✅ <strong>MATCH</strong> — The file's {{ match_algo }} digest matches
        your expected hash. The file has not been altered.
      </div>
      {% elif match_status == "MISMATCH" %}
      <div class="alert alert--mismatch">
        ❌ <strong>MISMATCH</strong> — No digest matches your expected hash.
        The file may have been modified, corrupted, or the wrong hash was entered.
      </div>
      {% endif %}

      <!-- Hash digest table -->
      <table class="hash-table">
        <thead>
          <tr>
            <th>Algorithm</th>
            <th>Digest</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          <tr class="hash-row hash-row--weak">
            <td class="algo-name">MD5</td>
            <td class="digest">
              <code>{{ results.md5 }}</code>
              <button class="copy-btn" data-clipboard="{{ results.md5 }}" title="Copy to clipboard">copy</button>
            </td>
            <td class="algo-note">⚠️ Weak — collisions known since 2004</td>
          </tr>
          <tr class="hash-row hash-row--weak">
            <td class="algo-name">SHA-1</td>
            <td class="digest">
              <code>{{ results.sha1 }}</code>
              <button class="copy-btn" data-clipboard="{{ results.sha1 }}" title="Copy to clipboard">copy</button>
            </td>
            <td class="algo-note">⚠️ Weak — SHAttered attack (2017)</td>
          </tr>
          <tr class="hash-row hash-row--strong">
            <td class="algo-name">SHA-256 ✓</td>
            <td class="digest">
              <code>{{ results.sha256 }}</code>
              <button class="copy-btn" data-clipboard="{{ results.sha256 }}" title="Copy to clipboard">copy</button>
            </td>
            <td class="algo-note">✅ Recommended — no collision attack known</td>
          </tr>
        </tbody>
      </table>

    </section>
    {% endif %}

    <!-- Educational explainer (always visible) -->
    <section class="tool-section explainer">
      <h2>How does hashing detect changes?</h2>
      <p>
        A <strong>cryptographic hash function</strong> converts any input — a text
        file, an executable, a video — into a fixed-length string called a
        <em>digest</em>. Two fundamental properties make hashes useful for
        integrity checking:
      </p>
      <ul>
        <li>
          <strong>Deterministic</strong> — the same input always produces the
          same digest. If you hash a file today and again in a year, an
          unmodified file gives an identical result.
        </li>
        <li>
          <strong>Avalanche effect</strong> — flipping even a single bit in the
          input produces a completely different digest. This makes silent
          tampering or accidental corruption detectable immediately.
        </li>
      </ul>
      <p>
        When a software publisher releases a download, they also publish its
        SHA-256 hash. After downloading, you hash the file yourself and compare —
        if the digests match, you know the bytes you received are exactly what the
        publisher signed.
      </p>

      <h2>Why are MD5 and SHA-1 considered weak?</h2>
      <p>
        A hash function is broken when an attacker can engineer a
        <strong>collision</strong> — two different files that produce the same
        digest. Once a collision is possible, a malicious file can be made to
        look identical to a legitimate one.
      </p>
      <ul>
        <li>
          <strong>MD5</strong> — Collision attacks have been practical since 2004.
          Attackers have used them to forge SSL certificates and spread malware.
          Never rely on MD5 for security decisions.
        </li>
        <li>
          <strong>SHA-1</strong> — Fully broken in 2017 by the
          <em>SHAttered</em> attack, which produced two real PDF files sharing the
          same SHA-1 digest. All major browsers stopped accepting SHA-1
          certificates years ago.
        </li>
        <li>
          <strong>SHA-256</strong> — No collision attack is known. Its 256-bit
          digest space (2^256 possible values) makes brute-force search
          astronomically infeasible. Use SHA-256 for all security-critical
          integrity checks.
        </li>
      </ul>
      <p class="explainer-note">
        Note: MD5 and SHA-1 are still reliable for detecting <em>accidental</em>
        corruption (download errors, bit-rot) — collisions require deliberate
        crafting. Their weakness is against <em>motivated attackers</em>.
      </p>
    </section>

    <!-- Copy-to-clipboard script (uses Clipboard API, supported in all modern browsers) -->
    <script>
      document.querySelectorAll('.copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var text = btn.getAttribute('data-clipboard');
          navigator.clipboard.writeText(text).then(function() {
            btn.textContent = 'copied!';
            setTimeout(function() { btn.textContent = 'copy'; }, 1500);
          });
        });
      });
    </script>
    <noscript>
      <p class="explainer-note">Enable JavaScript to use the one-click copy buttons.</p>
    </noscript>

  </main>

  <!-- Footer -->
  <footer class="footer">
    <p>HashCheck: File Integrity Verifier</p>
  </footer>

</body>
</html>
"""


# =============================================================================
# Routes
# =============================================================================

@app.route("/")
def index():
    """Root — redirect to the hash tool."""
    return redirect(url_for("hash_tool"))


@app.route("/hash", methods=["GET", "POST"])
def hash_tool():
    """
    Hash & Integrity Checker.

    GET  — renders the empty upload form.
    POST — reads the uploaded file stream in 64 KB chunks, computes MD5 /
           SHA-1 / SHA-256, optionally compares against an expected hash,
           and re-renders the page with results.
           The file is NEVER written to disk.
    """
    if request.method == "GET":
        return render_template_string(TEMPLATE)

    # ── POST: process the uploaded file ──────────────────────────────────────

    uploaded = request.files.get("file")

    # Normalise the expected hash: lowercase + strip all whitespace.
    # This lets users paste hashes like "a3 f1 …" (space-separated bytes)
    # and still get a correct comparison.
    expected = "".join(request.form.get("expected", "").split()).lower()

    # Validate that a file was attached and has a name.
    if not uploaded or not uploaded.filename:
        return render_template_string(
            TEMPLATE,
            error="No file was selected. Please choose a file and try again.",
            expected=expected,
        )

    # Compute all three digests by streaming the file in 64 KB chunks.
    # FileStorage.stream is the raw binary stream — never saved to disk.
    hashes = compute_hashes(uploaded.stream)

    # Measure file size: seek to end, read position.
    uploaded.stream.seek(0, 2)
    n_bytes = uploaded.stream.tell()
    file_size = _human_size(n_bytes)

    # Friendly error for empty files — hashing succeeds but the result is
    # meaningless and would confuse the user.
    if n_bytes == 0:
        return render_template_string(
            TEMPLATE,
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
        # Detect the algorithm from the hash length:
        #   32 chars → MD5, 40 chars → SHA-1, 64 chars → SHA-256
        algo_map = {
            32: ("md5",    "MD5"),
            40: ("sha1",   "SHA-1"),
            64: ("sha256", "SHA-256"),
        }
        algo_key, algo_label = algo_map.get(len(expected), (None, "unknown"))

        if algo_key and hashes[algo_key] == expected:
            match_status = "MATCH"
            match_algo   = algo_label
        else:
            match_status = "MISMATCH"
            match_algo   = algo_label if algo_key else "any algorithm"

    return render_template_string(
        TEMPLATE,
        filename=uploaded.filename,
        file_size=file_size,
        results=hashes,
        expected=expected,
        match_status=match_status,
        match_algo=match_algo,
    )


# =============================================================================
# Error handlers
# =============================================================================

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(e):
    """Return a friendly page when the upload exceeds MAX_CONTENT_LENGTH (16 MB)."""
    return render_template_string(
        TEMPLATE,
        error="The uploaded file exceeds the 16 MB limit. Please choose a smaller file.",
    ), 413


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    # debug=False — never enable debug in production; it allows arbitrary
    # code execution via the interactive browser debugger.
    app.run(host="127.0.0.1", port=5000, debug=False)
