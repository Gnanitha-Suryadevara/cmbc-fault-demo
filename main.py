"""
GenAI Embedded Testing backend (CS 697), hardened for public hosting.

Pipeline per request:
  1. Run CBMC on the ORIGINAL code (baseline).
  2. Apply a deterministic fault-injection mutation for the chosen fault type.
  3. Run CBMC on the MUTATED code.
  4. Report whether the injected fault was detected.

A fault counts as "detected" only when the baseline has no real violations and
the mutant violates a check the baseline does not.

Because this runs a C preprocessor and verifier on code from the internet, the
server enforces: size limits, a header whitelist (no file reads through
#include), per-run CPU/memory/file limits, a concurrency cap, and a per-IP
rate limit. It also serves index.html so the page and API share one origin.
"""
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections import defaultdict, deque
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CBMC_BIN = os.environ.get("CBMC_PATH", "cbmc")
TIMEOUT_SECONDS = int(os.environ.get("CBMC_TIMEOUT", "20"))
MAX_CODE_CHARS = int(os.environ.get("MAX_CODE_CHARS", "20000"))
MAX_UNWIND = int(os.environ.get("MAX_UNWIND", "20"))
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT", "2"))
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT", "15"))
MEMORY_LIMIT_BYTES = int(os.environ.get("MEM_LIMIT_MB", "2048")) * 1024 * 1024
MAX_OUTPUT_CHARS = 60000

ALLOWED_HEADERS = {
    "stdlib.h", "stdint.h", "stddef.h", "stdbool.h",
    "string.h", "stdio.h", "assert.h", "limits.h",
}

app = FastAPI(title="GenAI Embedded Testing Backend")

# No credentials are used, so a wildcard origin is valid (needed when
# index.html is opened from file:// during local development).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CBMC exit codes: 0 = verified, 10 = property violated, 6 = parse/convert error.
CBMC_STATUS = {0: "VERIFIED", 10: "BUG_FOUND", 6: "PARSE_ERROR"}


class VerificationRequest(BaseModel):
    code: str = Field(..., max_length=MAX_CODE_CHARS)
    fault_type: str
    function: Optional[str] = Field(None, max_length=64)
    unwind: int = Field(10, ge=1, le=MAX_UNWIND)
    inject: bool = True  # False = verify the code as given, no mutation


# ---------------------------------------------------------------------------
# Abuse protection
# ---------------------------------------------------------------------------

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)
_hits = defaultdict(deque)
_hits_lock = threading.Lock()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


def allow_request(ip: str) -> bool:
    now = time.monotonic()
    with _hits_lock:
        if len(_hits) > 5000:  # drop idle clients so the table cannot grow forever
            for key in [k for k, q in _hits.items() if not q or now - q[-1] > 60]:
                del _hits[key]
        q = _hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MIN:
            return False
        q.append(now)
        return True


INCLUDE_LINE = re.compile(r"^[ \t]*#[ \t]*include[ \t]*<([A-Za-z0-9_./]+)>[ \t]*$", re.MULTILINE)
INCLUDE_WORDS = re.compile(r"\b(?:include|include_next|import|embed)\b|__has_include|__has_embed")
FUNC_NAME = re.compile(r"^[A-Za-z_]\w{0,63}$")


def sanitize_code(code: str) -> str:
    """Normalise line endings, then allow only whitelisted <header.h> includes.

    Any mention of include/import/embed must be one of the whitelisted include
    lines, so no other directive (quoted, macro-built, digraph, commented-out
    prefix) can make the preprocessor read files from the server.
    """
    if "\x00" in code:
        raise HTTPException(status_code=400, detail="Code contains a null byte.")
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    code = re.sub(r"\\[ \t]*\n", "", code)  # join line continuations before checking

    allowed = INCLUDE_LINE.findall(code)
    bad = [h for h in allowed if h not in ALLOWED_HEADERS]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"Header not allowed: {bad[0]}. Allowed: {', '.join(sorted(ALLOWED_HEADERS))}.",
        )
    if len(INCLUDE_WORDS.findall(code)) != len(allowed):
        raise HTTPException(
            status_code=400,
            detail="Only lines of the form #include <header.h> with a standard header are allowed "
                   "(the words include/import/embed cannot appear elsewhere, even in comments).",
        )
    return code


# ---------------------------------------------------------------------------
# Fault injection (deterministic mutation operators)
# ---------------------------------------------------------------------------

def mutate_overflow(code: str) -> Tuple[str, Optional[str]]:
    """Turn the first strict loop bound `i < n` into `i <= n` (off-by-one)."""
    pattern = re.compile(r"(for\s*\([^;]*;\s*\w+\s*)<(\s*[^;=]+;)")
    new_code, n = pattern.subn(r"\1<=\2", code, count=1)
    if n == 0:
        return code, None
    return new_code, "Changed first for-loop bound '<' to '<=' (off-by-one)"


def mutate_leak(code: str) -> Tuple[str, Optional[str]]:
    """Delete the first free(...) call."""
    pattern = re.compile(r"^[ \t]*free\s*\([^;]*\)\s*;[ \t]*\n?", re.MULTILINE)
    new_code, n = pattern.subn("", code, count=1)
    if n == 0:
        return code, None
    return new_code, "Removed first free() call (missing free)"


def mutate_nondet(code: str) -> Tuple[str, Optional[str]]:
    """Strip the initializer from the first scalar local declared in a function body.

    CBMC treats an uninitialized local as a nondeterministic value and has no
    built-in uninitialized-read check, so this fault is often missed.
    """
    pattern = re.compile(
        r"(\{[^{}]*?\n[ \t]+)((?:unsigned\s+)?(?:int|char|short|long|uint\w*_t|int\w*_t)\s+\w+)\s*=\s*[^;]+;"
    )
    new_code, n = pattern.subn(r"\1\2;", code, count=1)
    if n == 0:
        return code, None
    return new_code, "Removed initializer from first scalar local (uninitialized read)"


MUTATORS = {
    "overflow": mutate_overflow,
    "leak": mutate_leak,
    "nondet": mutate_nondet,
}


# ---------------------------------------------------------------------------
# CBMC runner
# ---------------------------------------------------------------------------

def detect_entry_point(code: str) -> Optional[str]:
    """Return the first non-main function definition found, if any."""
    pattern = re.compile(
        r"^\s*(?:static\s+)?(?:[A-Za-z_][\w\s\*]*?)\s+\**([A-Za-z_]\w*)\s*\([^;{)]*\)\s*\{",
        re.MULTILINE,
    )
    for match in pattern.finditer(code):
        name = match.group(1)
        if name not in {"if", "for", "while", "switch", "main"}:
            return name
    return None


RESULT_LINE = re.compile(r"^\s*\[([^\]]+)\]\s.*:\s(SUCCESS|FAILURE|UNKNOWN)\s*$", re.MULTILINE)


def parse_failures(output: str) -> Tuple[list, list]:
    """Split failed checks into real property violations and unwinding-bound failures."""
    real, unwind = [], []
    for name, verdict in RESULT_LINE.findall(output):
        if verdict != "FAILURE":
            continue
        (unwind if ".unwind." in name else real).append(name)
    return real, unwind


def _limit_resources():  # runs in the child process before exec (POSIX only)
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT_SECONDS + 5, TIMEOUT_SECONDS + 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))


def run_cbmc(code: str, function: Optional[str], unwind: int) -> dict:
    posix = os.name == "posix"
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "target.c"), "w", newline="\n") as f:
            f.write(code)

        # --gcc avoids the MSVC preprocessor on Windows. --unwinding-assertions
        # makes an incomplete unwind a failure instead of a silent pass.
        cmd = [
            CBMC_BIN, "target.c", "--gcc",
            "--bounds-check", "--pointer-check", "--memory-leak-check",
            "--unwind", str(unwind), "--unwinding-assertions",
        ]
        if function:
            cmd += ["--function", function]

        kwargs = {}
        if posix:
            kwargs = dict(
                preexec_fn=_limit_resources,
                start_new_session=True,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
            )
        proc = subprocess.Popen(
            cmd, cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs
        )
        try:
            stdout, stderr = proc.communicate(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            if posix:
                os.killpg(proc.pid, signal.SIGKILL)  # also kills gcc/solver children
            else:
                proc.kill()
            proc.communicate()
            return {"status": "TIMEOUT", "returncode": None,
                    "output": f"CBMC exceeded {TIMEOUT_SECONDS}s",
                    "command": " ".join(cmd), "failed_checks": [], "unwind_failures": []}

    output = (stdout + "\n" + stderr)[:MAX_OUTPUT_CHARS]
    status = CBMC_STATUS.get(proc.returncode, "TOOL_ERROR")
    real, unwind_fail = parse_failures(output)
    if status == "BUG_FOUND" and not real and unwind_fail:
        # Only the unwinding assertion failed: the bound was too low to conclude.
        status = "INCOMPLETE"
    return {
        "status": status,
        "returncode": proc.returncode,
        "output": output,
        "command": " ".join(cmd),
        "failed_checks": real,
        "unwind_failures": unwind_fail,
    }


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

_version_cache: Optional[str] = None


def cbmc_version() -> Optional[str]:
    global _version_cache
    if _version_cache is None and shutil.which(CBMC_BIN):
        try:
            out = subprocess.run([CBMC_BIN, "--version"], capture_output=True, text=True, timeout=10)
            _version_cache = out.stdout.strip().split("\n")[0]
        except Exception:
            return None
    return _version_cache


@app.get("/")
def index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/health")
def health():
    return {"cbmc_found": shutil.which(CBMC_BIN) is not None, "cbmc_version": cbmc_version()}


@app.post("/verify")
def verify_code(req: VerificationRequest, request: Request):
    if not allow_request(client_ip(request)):
        raise HTTPException(status_code=429, detail=f"Rate limit: {RATE_LIMIT_PER_MIN} requests per minute.")
    if shutil.which(CBMC_BIN) is None:
        raise HTTPException(status_code=500, detail=f"'{CBMC_BIN}' not found on PATH.")
    if req.fault_type not in MUTATORS:
        raise HTTPException(status_code=400,
                            detail=f"Unknown fault_type '{req.fault_type}'. Use one of {sorted(MUTATORS)}.")
    if req.function and not FUNC_NAME.match(req.function):
        raise HTTPException(status_code=400, detail="Invalid function name.")

    code = sanitize_code(req.code)

    if not _slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="Server is busy verifying other requests. Try again in a few seconds.")
    try:
        function = req.function or detect_entry_point(code)
        baseline = run_cbmc(code, function, req.unwind)

        if not req.inject:
            return {"status": baseline["status"], "function": function,
                    "baseline": baseline, "mutant": None, "mutation": None,
                    "fault_detected": None, "output": baseline["output"]}

        mutated_code, description = MUTATORS[req.fault_type](code)
        if description is None:
            return {"status": "NO_MUTATION_SITE", "function": function,
                    "baseline": baseline, "mutant": None, "mutation": None,
                    "fault_detected": None,
                    "output": f"No applicable site for '{req.fault_type}' in this code.\n\n"
                              + baseline["output"]}

        mutant = run_cbmc(mutated_code, function, req.unwind)
    finally:
        _slots.release()

    # Detected = the mutant violates a check that the baseline does not.
    new_failures = sorted(set(mutant["failed_checks"]) - set(baseline["failed_checks"]))
    baseline_ok = baseline["status"] in ("VERIFIED", "INCOMPLETE")
    detected = baseline_ok and mutant["status"] == "BUG_FOUND" and len(new_failures) > 0

    if not baseline_ok:
        status = "BASELINE_" + baseline["status"]
    elif detected:
        status = "FAULT_DETECTED"
    elif mutant["status"] in ("VERIFIED", "INCOMPLETE"):
        status = "FAULT_MISSED"
    else:
        status = mutant["status"]

    return {
        "status": status,
        "function": function,
        "mutation": description,
        "fault_detected": detected,
        "new_failures": new_failures,
        "baseline": baseline,
        "mutant": mutant,
        "mutated_code": mutated_code,
        "output": (
            f"[baseline] {baseline['status']}\n[mutation] {description}\n"
            f"[mutant] {mutant['status']}\n\n--- MUTANT CBMC OUTPUT ---\n{mutant['output']}"
        ),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
