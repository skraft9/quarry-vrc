#!/usr/bin/env python3
"""Guard the lead-ref numbering invariants. Exit 1 on a hard violation.

Refs are numbered per target with a globally-unique letter prefix: each target owns one
prefix (the first target is A, the second B, and so on), no prefix is shared by two
targets, and no two lead notes ever carry the same ref. See standards/LEAD_STANDARD.md
for the scheme.

HARD FAILURES (exit 1):
  - two lead notes carry the same ref,
  - one letter prefix is claimed by more than one target.

REPORTED, not failed: class-scoped notes with no ref at all. Most are surface maps or
round analysis rather than findings, so a human decides whether each needs a ref; the
top-level notes/*.md round logs are exempt by construction (class NULL).

Runs off the markdown on disk (the system of record), so it is valid before an ingest.
"""
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "core"))

import common  # noqa: E402
import ingest  # noqa: E402

LETTER_RE = re.compile(r"^([A-Z]{1,2})\d+$")


def workspaces(root):
    prefix = getattr(common, "WORKSPACE_GLOB_PREFIX", "vulns_")
    out = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for name in names:
        p = os.path.join(root, name)
        if name.startswith(prefix) and os.path.isdir(p):
            out.append(p)
    return out


def scan(root):
    ref_files = collections.defaultdict(list)       # ref -> [path, ...]
    letter_targets = collections.defaultdict(set)    # prefix -> {target_slug, ...}
    blank_findings = []                              # class-scoped notes with no ref
    for ws in workspaces(root):
        slug = ingest.workspace_slug(ws)
        for path in ingest.iter_markdown(ws):
            info = ingest.classify_path(path, root)
            if not info or info.get("kind") != "lead":
                continue
            text = ingest.read_text(path)
            if text is None:
                continue
            ref = ingest.parse_lead(path, text).get("ref")
            if ref:
                ref_files[ref].append(path)
                m = LETTER_RE.match(ref)
                if m:
                    letter_targets[m.group(1)].add(slug)
            elif info.get("class") is not None:
                blank_findings.append(path)
    return ref_files, letter_targets, blank_findings


def main():
    root = common.HUNT_ROOT
    ref_files, letter_targets, blank_findings = scan(root)
    rel = lambda p: os.path.relpath(p, root)

    fails = 0
    dups = {r: fs for r, fs in ref_files.items() if len(fs) > 1}
    if dups:
        fails += len(dups)
        print("DUPLICATE REFS (%d) - each ref must be unique:" % len(dups))
        for r, fs in sorted(dups.items()):
            print("  %s" % r)
            for f in sorted(fs):
                print("      %s" % rel(f))

    shared = {L: ts for L, ts in letter_targets.items() if len(ts) > 1}
    if shared:
        fails += len(shared)
        print("PREFIX SHARED BY >1 TARGET (%d) - one prefix per target:" % len(shared))
        for L, ts in sorted(shared.items()):
            print("  %s -> %s" % (L, ", ".join(sorted(ts))))

    if blank_findings:
        print("\nclass-scoped notes with no ref (%d) - review; assign a ref if a finding:"
              % len(blank_findings))
        for f in sorted(blank_findings):
            print("  %s" % rel(f))

    if fails:
        print("\nFAIL: %d hard ref-integrity violation(s). See standards/LEAD_STANDARD.md."
              % fails)
        return 1

    total = sum(len(v) for v in ref_files.values())
    print("OK: %d refs, all unique across %d prefixes, one target per prefix."
          % (total, len(letter_targets)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
