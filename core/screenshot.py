#!/usr/bin/env python3
"""Screenshot and evidence capture for bug bounty submissions. Stdlib only.

Three capture backends, tried in order of preference:

  1. Caido   -- pull request/response renders via the GraphQL API (localhost:8080)
  2. Burp    -- export selected items via the REST API (localhost:1337)
  3. OS      -- platform screencapture (macOS `screencapture`, Linux `scrot` / `import`)

Each backend produces a file saved into the workspace's evidence directory. The file
is recorded in the uploads table so the Files tab and the submission workflow can
reference it.

Additional features beyond single capture:

  * Evidence timeline  -- collect all evidence for a lead into a chronological markdown
                          narrative ready to paste into Steps To Reproduce.
  * Proxy feed         -- pull recent Caido/Burp proxy history filtered by in-scope hosts
                          and auto-file matching requests as evidence.
  * Attachment collect  -- gather all evidence files for a workspace, ready for upload
                          alongside a HackerOne report submission.

CLI:
    python3 screenshot.py --detect                       # show available backends
    python3 screenshot.py --capture --target <slug>      # OS screenshot, filed to workspace
    python3 screenshot.py --caido --request-id 42        # pull Caido request #42
    python3 screenshot.py --burp --port 1337             # pull from Burp proxy history
    python3 screenshot.py --timeline --target <slug>     # build evidence timeline
    python3 screenshot.py --feed --target <slug>         # pull matching proxy traffic
    python3 screenshot.py --collect --target <slug>      # list evidence for attachment
"""
import argparse
import hashlib
import json
import mimetypes
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import common

EVIDENCE_DIR = "evidence"
# KNOWN LIMITATION (maintainer note, v1.4.0): these loopback defaults reach a proxy only
# when screenshot.py runs on the SAME host as Caido/Burp. Inside the shipped docker deployment
# 127.0.0.1 is the container, not the operator's machine, so set CAIDO_URL / BURP_URL to
# http://host.docker.internal:<port> (or the host IP) there. OS screen capture is host-only
# (no display or capture binary in the stdlib-only image). Tracked as a follow-up.
CAIDO_DEFAULT_URL = "http://127.0.0.1:8080"
BURP_DEFAULT_URL = "http://127.0.0.1:1337"


# ---------------------------------------------------------------- detection

def detect_backends():
    """Return a dict of available screenshot backends and their status."""
    out = {}

    # OS-level
    os_tool = _find_os_tool()
    out["os"] = {
        "available": os_tool is not None,
        "tool": os_tool,
        "platform": platform.system(),
    }

    # Caido
    caido_url = os.environ.get("CAIDO_URL") or CAIDO_DEFAULT_URL
    caido_ok = _probe_caido(caido_url)
    out["caido"] = {
        "available": caido_ok,
        "url": caido_url,
    }

    # Burp
    burp_url = os.environ.get("BURP_URL") or BURP_DEFAULT_URL
    burp_ok = _probe_burp(burp_url)
    out["burp"] = {
        "available": burp_ok,
        "url": burp_url,
    }

    return out


def _find_os_tool():
    """Return the name of the first available OS screenshot binary, or None."""
    if platform.system() == "Darwin":
        if shutil.which("screencapture"):
            return "screencapture"
    for tool in ("scrot", "gnome-screenshot", "import", "xfce4-screenshooter"):
        if shutil.which(tool):
            return tool
    return None


def _http_get(url, timeout=5):
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(), r.status
    except Exception:
        return None, 0


def _http_post_json(url, payload, timeout=10, headers=None):
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8")), r.status
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:500]
        except Exception:
            pass
        return {"error": str(e), "body": body}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def _probe_caido(base_url):
    """Check if Caido is reachable by hitting its GraphQL endpoint."""
    payload = {"query": "{ __typename }"}
    url = base_url.rstrip("/") + "/graphql"
    result, status = _http_post_json(url, payload, timeout=3)
    return status == 200 and isinstance(result, dict) and "data" in result


def _probe_burp(base_url):
    """Check if Burp Suite REST API is reachable."""
    url = base_url.rstrip("/") + "/v0.1/version"
    body, status = _http_get(url, timeout=3)
    return status == 200


# ---------------------------------------------------------------- file naming

def _evidence_path(workspace, target_slug, name, ext=".png"):
    """Build the destination path under <workspace>/evidence/<name>.<ext>."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    slug = common.slugify(name or "screenshot", 60)
    filename = "%s_%s%s" % (stamp, slug, ext)
    base = workspace or common.HUNT_ROOT
    if target_slug:
        candidate = os.path.join(base, "vulns_%s" % target_slug, EVIDENCE_DIR, filename)
    else:
        candidate = os.path.join(base, EVIDENCE_DIR, filename)
    return candidate


def _save_binary(path, data):
    """Write binary data atomically, creating parent dirs. Returns (path, sha256, size)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
    digest = hashlib.sha256(data).hexdigest()
    return path, digest, len(data)


def _record_upload(conn, path, sha256, size, actor="cli"):
    """Insert into the uploads table so the file appears in the Files tab."""
    filename = os.path.basename(path)
    mime = mimetypes.guess_type(filename)[0] or "image/png"
    conn.execute(
        "INSERT INTO uploads (filename, stored_path, filed_to, mime, size, sha256,"
        " uploaded_at, uploaded_by) VALUES (?,?,?,?,?,?,?,?)",
        (filename, path, path, mime, size, sha256, common.now_iso(), actor))
    conn.commit()
    upload_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    common.audit(conn, actor, "screenshot", "upload", upload_id, path)
    return upload_id


# ---------------------------------------------------------------- OS capture

def capture_os(target_slug=None, workspace=None, name=None, mode="interactive"):
    """Take a screenshot using the OS tool. Returns the saved file path, or raises.

    Modes:
      interactive  -- user selects a region (macOS -i, scrot -s, import)
      fullscreen   -- capture the entire screen
      window       -- capture the focused window (macOS -w)
    """
    tool = _find_os_tool()
    if not tool:
        raise RuntimeError("no screenshot tool found on this system")

    dest = _evidence_path(workspace, target_slug, name or "screen")
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    cmd = _build_os_cmd(tool, dest, mode)
    result = subprocess.run(cmd, capture_output=True, timeout=60)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError("screenshot failed (exit %d): %s" % (result.returncode, stderr))
    if not os.path.isfile(dest):
        raise RuntimeError("screenshot tool exited 0 but no file at %s" % dest)
    return dest


def _build_os_cmd(tool, dest, mode):
    if tool == "screencapture":
        flags = {
            "interactive": ["-i"],
            "fullscreen": [],
            "window": ["-w"],
        }.get(mode, ["-i"])
        return ["screencapture"] + flags + [dest]
    if tool == "scrot":
        flags = {
            "interactive": ["-s"],
            "fullscreen": [],
            "window": ["-u"],
        }.get(mode, ["-s"])
        return ["scrot"] + flags + [dest]
    if tool == "import":
        if mode == "fullscreen":
            return ["import", "-window", "root", dest]
        return ["import", dest]
    if tool == "gnome-screenshot":
        flags = {
            "interactive": ["-a"],
            "fullscreen": [],
            "window": ["-w"],
        }.get(mode, ["-a"])
        return ["gnome-screenshot"] + flags + ["-f", dest]
    return [tool, dest]


# ---------------------------------------------------------------- Caido

def capture_caido(request_id=None, target_slug=None, workspace=None, name=None,
                  base_url=None, auth_token=None):
    """Pull a request/response from Caido and save as a text render (PNG via reportlab
    is not stdlib, so we save the HTTP exchange as a formatted text file).

    If request_id is None, pulls the most recent request from the proxy history.
    Returns the saved file path.
    """
    url = (base_url or os.environ.get("CAIDO_URL") or CAIDO_DEFAULT_URL).rstrip("/")
    headers = {}
    if auth_token:
        headers["Authorization"] = "Bearer " + auth_token

    if request_id:
        query = """
        query GetRequest($id: ID!) {
          request(id: $id) {
            id
            host
            port
            method
            path
            query
            raw
            createdAt
            response {
              statusCode
              raw
            }
          }
        }
        """
        variables = {"id": str(request_id)}
    else:
        query = """
        query GetLatest {
          requests(first: 1, order: { by: ID, ordering: DESC }) {
            edges {
              node {
                id
                host
                port
                method
                path
                query
                raw
                createdAt
                response {
                  statusCode
                  raw
                }
              }
            }
          }
        }
        """
        variables = {}

    payload = {"query": query, "variables": variables}
    result, status = _http_post_json(url + "/graphql", payload, headers=headers)

    if status != 200 or "errors" in (result or {}):
        raise RuntimeError("Caido API error (HTTP %d): %s" % (status, json.dumps(result)[:300]))

    data = result.get("data") or {}
    if request_id:
        node = data.get("request")
    else:
        edges = (data.get("requests") or {}).get("edges") or []
        node = edges[0]["node"] if edges else None

    if not node:
        raise RuntimeError("no request found in Caido" +
                           (" (id=%s)" % request_id if request_id else ""))

    # Build a readable text render of the HTTP exchange
    lines = []
    lines.append("=" * 72)
    lines.append("Caido Capture - Request #%s" % node.get("id", "?"))
    lines.append("Captured: %s" % node.get("createdAt", ""))
    lines.append("=" * 72)
    lines.append("")

    req_raw = node.get("raw") or ""
    if req_raw:
        lines.append("--- REQUEST ---")
        lines.append(req_raw if isinstance(req_raw, str) else str(req_raw))
    else:
        lines.append("--- REQUEST ---")
        lines.append("%s %s%s HTTP/1.1" % (
            node.get("method", "GET"),
            node.get("path", "/"),
            ("?" + node["query"]) if node.get("query") else ""))
        lines.append("Host: %s%s" % (
            node.get("host", ""),
            (":%s" % node["port"]) if node.get("port") and node["port"] != 443 else ""))

    resp = node.get("response") or {}
    resp_raw = resp.get("raw") or ""
    if resp_raw or resp.get("statusCode"):
        lines.append("")
        lines.append("--- RESPONSE (HTTP %s) ---" % (resp.get("statusCode") or "?"))
        if resp_raw:
            lines.append(resp_raw if isinstance(resp_raw, str) else str(resp_raw))

    lines.append("")
    lines.append("=" * 72)
    text = "\n".join(lines)

    label = name or ("caido-%s-%s" % (node.get("host", "unknown"), node.get("id", "0")))
    dest = _evidence_path(workspace, target_slug, label, ext=".txt")
    path, digest, size = _save_binary(dest, text.encode("utf-8"))
    return path


# ---------------------------------------------------------------- Burp Suite

def capture_burp(item_index=None, target_slug=None, workspace=None, name=None,
                 base_url=None):
    """Pull proxy history items from Burp Suite REST API and save as text.

    Burp Pro exposes a REST API on localhost:1337 (configurable). The /v0.1/proxy/history
    endpoint returns the proxy history. If item_index is None, pulls the most recent item.
    Returns the saved file path.
    """
    url = (base_url or os.environ.get("BURP_URL") or BURP_DEFAULT_URL).rstrip("/")

    # Fetch proxy history
    history_url = url + "/v0.1/proxy/history"
    body, status = _http_get(history_url, timeout=10)
    if status != 200 or not body:
        raise RuntimeError("Burp API unreachable or returned HTTP %d" % status)

    try:
        items = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("Burp API returned non-JSON response")

    if not items:
        raise RuntimeError("Burp proxy history is empty")

    if item_index is not None:
        if item_index < 0 or item_index >= len(items):
            raise RuntimeError("item index %d out of range (history has %d items)"
                               % (item_index, len(items)))
        item = items[item_index]
    else:
        item = items[-1]

    # Fetch full request/response for this item
    item_url = url + "/v0.1/proxy/history/%s" % (item.get("serial_number") or item_index or 0)
    detail_body, detail_status = _http_get(item_url, timeout=10)

    lines = []
    lines.append("=" * 72)
    lines.append("Burp Suite Capture")
    lines.append("Captured: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("=" * 72)
    lines.append("")

    host = item.get("host") or item.get("ip") or "unknown"
    method = item.get("method") or "?"
    path = item.get("path") or item.get("url") or "/"
    status_code = item.get("status") or "?"

    lines.append("--- REQUEST ---")
    if detail_body and detail_status == 200:
        try:
            detail = json.loads(detail_body.decode("utf-8"))
            req_text = detail.get("request") or ""
            if req_text:
                lines.append(req_text if isinstance(req_text, str) else str(req_text))
            else:
                lines.append("%s %s HTTP/1.1" % (method, path))
                lines.append("Host: %s" % host)
        except (ValueError, UnicodeDecodeError):
            lines.append("%s %s HTTP/1.1" % (method, path))
            lines.append("Host: %s" % host)
    else:
        lines.append("%s %s HTTP/1.1" % (method, path))
        lines.append("Host: %s" % host)

    lines.append("")
    lines.append("--- RESPONSE (HTTP %s) ---" % status_code)
    if detail_body and detail_status == 200:
        try:
            detail = json.loads(detail_body.decode("utf-8"))
            resp_text = detail.get("response") or ""
            if resp_text:
                lines.append(resp_text if isinstance(resp_text, str) else str(resp_text))
        except (ValueError, UnicodeDecodeError):
            pass

    lines.append("")
    lines.append("=" * 72)
    text = "\n".join(lines)

    label = name or ("burp-%s-%s" % (host, method.lower()))
    dest = _evidence_path(workspace, target_slug, label, ext=".txt")
    path, digest, size = _save_binary(dest, text.encode("utf-8"))
    return path


# ---------------------------------------------------------------- unified capture

def capture(backend="auto", target_slug=None, workspace=None, name=None,
            request_id=None, item_index=None, mode="interactive",
            caido_url=None, burp_url=None, caido_token=None, conn=None):
    """Unified capture entry point. Returns dict with path, backend used, and metadata.

    backend: 'auto' tries caido -> burp -> os in order.
             'caido', 'burp', 'os' forces one backend.
    """
    backends = detect_backends() if backend == "auto" else {}

    if backend == "auto":
        if backends.get("caido", {}).get("available") and request_id is not None:
            backend = "caido"
        elif backends.get("burp", {}).get("available") and item_index is not None:
            backend = "burp"
        elif backends.get("os", {}).get("available"):
            backend = "os"
        elif backends.get("caido", {}).get("available"):
            backend = "caido"
        elif backends.get("burp", {}).get("available"):
            backend = "burp"
        else:
            raise RuntimeError("no screenshot backend available")

    if backend == "caido":
        path = capture_caido(
            request_id=request_id, target_slug=target_slug, workspace=workspace,
            name=name, base_url=caido_url, auth_token=caido_token)
    elif backend == "burp":
        path = capture_burp(
            item_index=item_index, target_slug=target_slug, workspace=workspace,
            name=name, base_url=burp_url)
    elif backend == "os":
        path = capture_os(
            target_slug=target_slug, workspace=workspace, name=name, mode=mode)
    else:
        raise RuntimeError("unknown backend: %s" % backend)

    result = {
        "ok": True,
        "backend": backend,
        "path": path,
        "filename": os.path.basename(path),
        "size": os.path.getsize(path),
    }

    if conn:
        with open(path, "rb") as fh:
            data = fh.read()
        digest = hashlib.sha256(data).hexdigest()
        result["upload_id"] = _record_upload(conn, path, digest, len(data))
        result["sha256"] = digest

    return result


# ---------------------------------------------------------------- evidence timeline

def _evidence_dir_for_target(target_slug, workspace=None):
    """Resolve the evidence directory for a target. Returns the absolute path."""
    base = workspace or common.HUNT_ROOT
    if target_slug:
        return os.path.join(base, "vulns_%s" % target_slug, EVIDENCE_DIR)
    return os.path.join(base, EVIDENCE_DIR)


def _list_evidence(target_slug, workspace=None):
    """List all evidence files for a target, sorted by mtime ascending (oldest first)."""
    edir = _evidence_dir_for_target(target_slug, workspace)
    if not os.path.isdir(edir):
        return []
    files = []
    for name in os.listdir(edir):
        full = os.path.join(edir, name)
        if not os.path.isfile(full):
            continue
        st = os.stat(full)
        files.append({
            "path": full,
            "name": name,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "mtime_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            "ext": os.path.splitext(name)[1].lower(),
            "mime": mimetypes.guess_type(name)[0] or "application/octet-stream",
        })
    files.sort(key=lambda f: f["mtime"])
    return files


def build_timeline(target_slug, workspace=None, lead_ref=None):
    """Build a chronological evidence timeline as markdown.

    Scans the workspace evidence directory, sorts by timestamp, and produces a
    markdown document with each piece of evidence as a numbered step. Text evidence
    (Caido/Burp captures) is inlined; binary files (screenshots) are referenced.

    Returns {"markdown": str, "files": list, "count": int}.
    """
    files = _list_evidence(target_slug, workspace)
    if not files:
        return {"markdown": "", "files": [], "count": 0}

    lines = []
    heading = "Evidence Timeline"
    if lead_ref:
        heading = "%s - Evidence Timeline" % lead_ref
    lines.append("## %s" % heading)
    lines.append("")
    lines.append("Collected %d pieces of evidence." % len(files))
    lines.append("")

    for i, f in enumerate(files, 1):
        lines.append("### Step %d - %s" % (i, f["name"]))
        lines.append("")
        lines.append("**Captured:** %s | **Size:** %d bytes" % (f["mtime_iso"], f["size"]))
        lines.append("")

        if f["ext"] in (".txt", ".md", ".json", ".xml", ".html"):
            try:
                with open(f["path"], "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                if len(content) > 8000:
                    content = content[:8000] + "\n\n... (truncated, %d bytes total)" % f["size"]
                lines.append("```")
                lines.append(content)
                lines.append("```")
            except OSError:
                lines.append("*File could not be read.*")
        elif f["ext"] in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
            lines.append("![%s](%s)" % (f["name"], f["path"]))
        else:
            lines.append("*Binary file: `%s` (%s, %d bytes)*" % (
                f["name"], f["mime"], f["size"]))

        lines.append("")

    return {"markdown": "\n".join(lines), "files": files, "count": len(files)}


def export_timeline(target_slug, workspace=None, lead_ref=None):
    """Build the timeline and save it as a markdown file in the evidence directory.

    Returns the path to the saved timeline file.
    """
    result = build_timeline(target_slug, workspace, lead_ref)
    if not result["count"]:
        raise RuntimeError("no evidence files found for target %s" % (target_slug or "(none)"))

    edir = _evidence_dir_for_target(target_slug, workspace)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(edir, "%s_timeline.md" % stamp)
    path, _, _ = _save_binary(dest, result["markdown"].encode("utf-8"))
    return path


# ---------------------------------------------------------------- proxy feed

def _scope_hosts(conn, target_slug):
    """Get in-scope hostnames for a target from the database.

    Pulls from the scopes table joined through the target's program. Returns a list
    of hostnames/identifiers that can be matched against proxy traffic.
    """
    if not conn or not target_slug:
        return []
    try:
        rows = conn.execute(
            "SELECT s.identifier FROM scopes s"
            " JOIN programs p ON p.id = s.program_id"
            " JOIN targets t ON t.program_id = p.id"
            " WHERE t.slug = ?", (target_slug,)).fetchall()
        hosts = []
        for r in rows:
            ident = (r[0] or "").strip()
            if not ident:
                continue
            ident = ident.replace("https://", "").replace("http://", "")
            ident = ident.split("/")[0].strip()
            if ident.startswith("*."):
                ident = ident[2:]
            if ident:
                hosts.append(ident.lower())
        return hosts
    except Exception:
        return []


def proxy_feed_caido(target_slug, hosts=None, workspace=None, limit=20,
                     base_url=None, auth_token=None, conn=None):
    """Pull recent Caido proxy history filtered by in-scope hosts.

    Fetches the last `limit` requests, filters by host match, and saves each matching
    request/response as evidence. Returns a list of saved file paths.
    """
    url = (base_url or os.environ.get("CAIDO_URL") or CAIDO_DEFAULT_URL).rstrip("/")
    hdrs = {}
    if auth_token:
        hdrs["Authorization"] = "Bearer " + auth_token

    if not hosts and conn:
        hosts = _scope_hosts(conn, target_slug)
    if not hosts:
        raise RuntimeError("no scope hosts found for target %s; pass --hosts or configure scopes"
                           % (target_slug or "(none)"))

    query = """
    query GetRecent($first: Int!) {
      requests(first: $first, order: { by: ID, ordering: DESC }) {
        edges {
          node {
            id
            host
            port
            method
            path
            query
            raw
            createdAt
            response {
              statusCode
              raw
            }
          }
        }
      }
    }
    """
    payload = {"query": query, "variables": {"first": min(limit * 3, 200)}}
    result, status = _http_post_json(url + "/graphql", payload, headers=hdrs)
    if status != 200:
        raise RuntimeError("Caido API error (HTTP %d)" % status)

    edges = ((result or {}).get("data") or {}).get("requests", {}).get("edges") or []
    saved = []
    for edge in edges:
        node = edge.get("node") or {}
        host = (node.get("host") or "").lower()
        if not any(host == h or host.endswith("." + h) for h in hosts):
            continue
        try:
            path = capture_caido(
                request_id=node["id"], target_slug=target_slug, workspace=workspace,
                base_url=base_url, auth_token=auth_token)
            if conn:
                with open(path, "rb") as fh:
                    data = fh.read()
                digest = hashlib.sha256(data).hexdigest()
                _record_upload(conn, path, digest, len(data))
            saved.append(path)
        except RuntimeError:
            continue
        if len(saved) >= limit:
            break

    return saved


def proxy_feed_burp(target_slug, hosts=None, workspace=None, limit=20,
                    base_url=None, conn=None):
    """Pull recent Burp proxy history filtered by in-scope hosts.

    Fetches proxy history, filters by host match, and saves each matching item
    as evidence. Returns a list of saved file paths.
    """
    url = (base_url or os.environ.get("BURP_URL") or BURP_DEFAULT_URL).rstrip("/")

    if not hosts and conn:
        hosts = _scope_hosts(conn, target_slug)
    if not hosts:
        raise RuntimeError("no scope hosts found for target %s; pass --hosts or configure scopes"
                           % (target_slug or "(none)"))

    body, status = _http_get(url + "/v0.1/proxy/history", timeout=10)
    if status != 200 or not body:
        raise RuntimeError("Burp API unreachable or returned HTTP %d" % status)

    try:
        items = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("Burp API returned non-JSON response")

    saved = []
    for i, item in enumerate(reversed(items)):
        host = (item.get("host") or item.get("ip") or "").lower()
        if not any(host == h or host.endswith("." + h) for h in hosts):
            continue
        try:
            path = capture_burp(
                item_index=len(items) - 1 - i, target_slug=target_slug,
                workspace=workspace, base_url=base_url)
            if conn:
                with open(path, "rb") as fh:
                    data = fh.read()
                digest = hashlib.sha256(data).hexdigest()
                _record_upload(conn, path, digest, len(data))
            saved.append(path)
        except RuntimeError:
            continue
        if len(saved) >= limit:
            break

    return saved


def proxy_feed(target_slug, backend="auto", hosts=None, workspace=None, limit=20,
               caido_url=None, burp_url=None, caido_token=None, conn=None):
    """Pull matching proxy traffic from Caido or Burp and save as evidence.

    Returns {"backend": str, "saved": list, "count": int, "hosts": list}.
    """
    scope_hosts = hosts
    if not scope_hosts and conn:
        scope_hosts = _scope_hosts(conn, target_slug)

    if backend == "auto":
        backends = detect_backends()
        if backends.get("caido", {}).get("available"):
            backend = "caido"
        elif backends.get("burp", {}).get("available"):
            backend = "burp"
        else:
            raise RuntimeError("no proxy backend available (need Caido or Burp running)")

    if backend == "caido":
        saved = proxy_feed_caido(
            target_slug, hosts=scope_hosts, workspace=workspace, limit=limit,
            base_url=caido_url, auth_token=caido_token, conn=conn)
    elif backend == "burp":
        saved = proxy_feed_burp(
            target_slug, hosts=scope_hosts, workspace=workspace, limit=limit,
            base_url=burp_url, conn=conn)
    else:
        raise RuntimeError("unknown proxy backend: %s" % backend)

    return {
        "backend": backend,
        "saved": saved,
        "count": len(saved),
        "hosts": scope_hosts or [],
    }


# ---------------------------------------------------------------- evidence collection for attachments

def collect_evidence(target_slug, workspace=None):
    """Gather all evidence files for a target, ready for attachment to a report.

    Returns a list of dicts with path, name, size, mime, and sha256 for each file.
    This is the input to the attachment upload flow in h1.py.
    """
    files = _list_evidence(target_slug, workspace)
    out = []
    for f in files:
        try:
            with open(f["path"], "rb") as fh:
                data = fh.read()
            f["sha256"] = hashlib.sha256(data).hexdigest()
        except OSError:
            f["sha256"] = ""
        out.append(f)
    return out


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description="Screenshot and evidence capture for submissions")

    g = ap.add_argument_group("capture")
    g.add_argument("--detect", action="store_true",
                   help="show available backends and exit")
    g.add_argument("--capture", action="store_true",
                   help="take an OS screenshot")
    g.add_argument("--caido", action="store_true",
                   help="pull from Caido proxy")
    g.add_argument("--burp", action="store_true",
                   help="pull from Burp Suite proxy")

    g = ap.add_argument_group("evidence management")
    g.add_argument("--timeline", action="store_true",
                   help="build evidence timeline markdown for a target")
    g.add_argument("--feed", action="store_true",
                   help="pull matching proxy traffic for a target (Caido/Burp)")
    g.add_argument("--collect", action="store_true",
                   help="list all evidence files for a target")

    g = ap.add_argument_group("options")
    g.add_argument("--target", metavar="SLUG",
                   help="workspace target slug (files to vulns_<slug>/evidence/)")
    g.add_argument("--name", metavar="LABEL",
                   help="label for the screenshot filename")
    g.add_argument("--ref", metavar="REF",
                   help="lead reference (e.g. F01) for timeline heading")
    g.add_argument("--request-id", metavar="ID",
                   help="Caido request id to capture")
    g.add_argument("--item-index", metavar="N", type=int,
                   help="Burp proxy history item index")
    g.add_argument("--mode", choices=("interactive", "fullscreen", "window"),
                   default="interactive",
                   help="OS capture mode (default: interactive)")
    g.add_argument("--hosts", metavar="HOST,HOST",
                   help="comma-separated hosts to filter proxy feed")
    g.add_argument("--limit", metavar="N", type=int, default=20,
                   help="max items for proxy feed (default: 20)")
    g.add_argument("--caido-url", metavar="URL",
                   help="Caido API URL (default: %s)" % CAIDO_DEFAULT_URL)
    g.add_argument("--burp-url", metavar="URL",
                   help="Burp REST API URL (default: %s)" % BURP_DEFAULT_URL)
    g.add_argument("--caido-token", metavar="TOKEN",
                   help="Caido authentication token")
    g.add_argument("--record", action="store_true",
                   help="record in the uploads table (requires the database)")
    args = ap.parse_args()

    if args.detect:
        backends = detect_backends()
        for name, info in backends.items():
            st = "YES" if info.get("available") else "no"
            detail = info.get("tool") or info.get("url") or ""
            print("  %-8s %-4s  %s" % (name, st, detail))
        return

    conn = None
    if args.record or args.feed or args.timeline or args.collect:
        try:
            conn = common.connect()
            common.init_db(conn)
        except Exception:
            pass

    try:
        if args.timeline:
            result = build_timeline(args.target, lead_ref=args.ref)
            if not result["count"]:
                print("no evidence files found")
                return
            path = export_timeline(args.target, lead_ref=args.ref)
            print("timeline: %s (%d files)" % (path, result["count"]))
            return

        if args.feed:
            if not args.target:
                sys.exit("--feed requires --target")
            hosts = [h.strip() for h in args.hosts.split(",")] if args.hosts else None
            backend = "caido" if args.caido else ("burp" if args.burp else "auto")
            result = proxy_feed(
                target_slug=args.target, backend=backend, hosts=hosts,
                limit=args.limit, caido_url=args.caido_url, burp_url=args.burp_url,
                caido_token=args.caido_token, conn=conn)
            print("feed: %d requests captured via %s (hosts: %s)" % (
                result["count"], result["backend"], ", ".join(result["hosts"])))
            for p in result["saved"]:
                print("  %s" % p)
            return

        if args.collect:
            files = collect_evidence(args.target)
            if not files:
                print("no evidence files found")
                return
            total = sum(f["size"] for f in files)
            print("evidence for %s: %d files, %d bytes total" % (
                args.target or "(all)", len(files), total))
            for f in files:
                print("  %-40s %8d  %s" % (f["name"], f["size"], f["mime"]))
            return

        if not (args.capture or args.caido or args.burp):
            ap.print_help()
            return

        backend = "os"
        if args.caido:
            backend = "caido"
        elif args.burp:
            backend = "burp"

        result = capture(
            backend=backend,
            target_slug=args.target,
            name=args.name,
            request_id=args.request_id,
            item_index=args.item_index,
            mode=args.mode,
            caido_url=args.caido_url,
            burp_url=args.burp_url,
            caido_token=args.caido_token,
            conn=conn,
        )
        print("saved: %s (%d bytes, backend=%s)" % (
            result["path"], result["size"], result["backend"]))
        if result.get("upload_id"):
            print("upload_id: %d" % result["upload_id"])
    except RuntimeError as e:
        sys.exit("error: %s" % e)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    main()
