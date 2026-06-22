"""Filter a smell manifest to only include the specified files.

Usage:
    python3 filter_manifest.py <src_json> <dst_json> <file1> <file2> [...]
"""
import json
import sys

src, dst, *keep = sys.argv[1:]
keep = set(keep)

data = json.loads(open(src).read())
entries = data["examples"] if isinstance(data, dict) else data
filtered = {"examples": [e for e in entries if e["file"] in keep]}

open(dst, "w").write(json.dumps(filtered, indent=4))
