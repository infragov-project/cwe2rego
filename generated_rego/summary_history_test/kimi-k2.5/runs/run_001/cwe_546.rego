package glitch

import data.glitch_lib

suspicious_patterns := {
    "BUG", "BUGFIX", "KNOWNBUG", "BUGBUG",
    "HACK", "WORKAROUND", "TEMP", "TEMPORARY", "KLUDGE",
    "FIXME", "FIX", "TODO", "TBD", "XXX",
    "LATER", "LATER2", "FUTURE", "DEBT", "TECHDEBT",
    "SECURITY", "INSECURE", "VULNERABILITY", "VULN", "BYPASS", "BACKDOOR",
    "REVIEW", "REVIEWME", "AUDIT", "CHECKME", "VERIFY",
    "DEPRECATED", "OBSOLETE"
}

strong_suspicious_patterns := {
    "FIXME", "TODO", "XXX", "HACK", "BUG", "VULNERABILITY", "VULN", "BACKDOOR", "BYPASS", "INSECURE", "SECURITY ISSUE", "SECURITY PROBLEM", "SECURITY FIX", "SECURITY HOLE", "SECURITY FLAW"
}

fragility_patterns := {
    "WILL BREAK", "CANNOT CHANGE", "WILL NOT WORK", "BREAKS?", "BROKEN", "FRAGILE", "UNSTABLE", "UNRELIABLE"
}

url_pattern := "^.*[A-Z]+://[^\\s]+/(ISSUES?|BUGS?)/[0-9]+.*$"

is_strong_suspicious(content) {
    upper_content := upper(content)
    pattern := strong_suspicious_patterns[_]
    regex.match(sprintf(".*\\b%s.*", [pattern]), upper_content)
}

is_url_reference(content) {
    upper_content := upper(content)
    regex.match(url_pattern, upper_content)
}

is_standard_suspicious(content) {
    upper_content := upper(content)
    pattern := suspicious_patterns[_]
    regex.match(sprintf(".*\\b%s\\b.*", [pattern]), upper_content)
	not is_benign_removal_language(upper_content)
}

is_benign_removal_language(content) {
    regex.match(".*REMOVED?\\s+(FROM|BY|IN|TO|THE|A|AN)\\s+.*", content)
}

is_benign_removal_language(content) {
    regex.match(".*(SHOULD|WILL|CAN|MAY|MIGHT)\\s+BE\\s+REMOVED.*", content)
}

is_fragility_indicator(content) {
    upper_content := upper(content)
    pattern := fragility_patterns[_]
    regex.match(sprintf(".*\\b%s\\b.*", [pattern]), upper_content)
}

is_suspicious_pattern(content) {
    is_strong_suspicious(content)
}

is_suspicious_pattern(content) {
    is_url_reference(content)
}

is_suspicious_pattern(content) {
    is_standard_suspicious(content)
}

is_suspicious_pattern(content) {
    is_fragility_indicator(content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    
    is_suspicious_pattern(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments containing security-relevant keywords, fragile implementation warnings, or issue tracker references may indicate incomplete fixes, known vulnerabilities, or unstable configurations. (CWE-546)"
    }
}