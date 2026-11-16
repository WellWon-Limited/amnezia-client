#!/usr/bin/env python3
# AVPN (Scanner, lane L4): the awg-apple package folder that belongs to THIS tree's recipe, from the local conan
# cache - the recipe revision whose exported files (conanmanifest.txt) equal the tree's recipe files, the shared
# vectors and the libxray patches the recipe exports; with no such revision, the newest one that has a binary.
# Revision timestamps alone are not enough: re-exporting an older recipe makes it the newest again.
# Usage: find_awg_apple_package.py <repo root> <os: iOS|Macos> [<ref>]  -> prints the package folder (exit 1: none)
import hashlib
import json
import os
import subprocess
import sys


def conan(*args):
    return subprocess.run(["conan", *args], capture_output=True, text=True).stdout


def tree_path(root, key):
    if key.startswith("export_source/vectors/"):
        return os.path.join(root, "client/core/serviceEngine/tests/vectors", os.path.basename(key))
    if key.startswith("export_source/"):
        rel = key[len("export_source/"):]
        for base in ("recipes/awg-apple", "recipes/amnezia-libxray"):
            p = os.path.join(root, base, rel)
            if os.path.exists(p):
                return p
        return None
    return os.path.join(root, "recipes/awg-apple", key)


def matches(root, export_folder):
    manifest = os.path.join(export_folder, "conanmanifest.txt")
    if not os.path.exists(manifest):
        return False
    with open(manifest, encoding="utf-8") as f:
        lines = f.read().splitlines()[1:]  # first line: the timestamp
    for line in lines:
        if ": " not in line:
            continue
        key, digest = line.rsplit(": ", 1)
        p = tree_path(root, key)
        if p is None or not os.path.exists(p):
            return False
        with open(p, "rb") as f:
            if hashlib.md5(f.read()).hexdigest() != digest:
                return False
    return True


def main():
    root, want_os = sys.argv[1], sys.argv[2]
    ref = sys.argv[3] if len(sys.argv) > 3 else "awg-apple/3.1.4-tribe.12"
    try:
        listing = json.loads(conan("list", f"{ref}#*:*", "--format=json") or "{}").get("Local Cache", {})
    except json.JSONDecodeError:
        listing = {}
    candidates = []
    for rr in listing.values():
        for rev, info in rr.get("revisions", {}).items():
            for pid, p in info.get("packages", {}).items():
                if p.get("info", {}).get("settings", {}).get("os") == want_os:
                    candidates.append((float(info.get("timestamp", 0)), rev, pid))
    if not candidates:
        return 1
    candidates.sort(reverse=True)
    chosen = None
    for _, rev, pid in candidates:
        export = conan("cache", "path", f"{ref}#{rev}").strip().splitlines()
        if export and matches(root, export[-1]):
            chosen = (rev, pid)
            break
    if chosen is None:
        chosen = (candidates[0][1], candidates[0][2])
        print(f"find_awg_apple_package: no revision matches this tree's recipe; newest with a {want_os} binary: "
              f"{chosen[0]}", file=sys.stderr)
    folder = conan("cache", "path", f"{ref}#{chosen[0]}:{chosen[1]}").strip().splitlines()
    if not folder:
        return 1
    print(folder[-1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
