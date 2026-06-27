package glitch

import data.glitch_lib

high_confidence_patterns := {"TODO", "FIXME", "XXX", "HACK", "BUG", "TEMP", "TEMPORARY", "LATER", "NEXT VERSION", "POST-DEPLOY", "FUTURE", "WIP", "PENDING", "INSECURE", "DISABLED FOR NOW", "BYPASS", "WORKAROUND", "DEBUG ONLY", "TEST ONLY", "DO NOT USE IN PROD", "BROKEN", "DEPRECATED"}

risk_amplifiers := {"disable verification", "skip check", "remove before", "placeholder certificate", "hardcoded", "default password", "change this", "replace me", "handle error", "error TBD", "exception ignored", "doing so will break", "cannot change this"}

is_suspicious_comment(content) {
    pattern := high_confidence_patterns[_]
    regex.match(sprintf("(?i)%s", [pattern]), content)
} else {
    pattern := risk_amplifiers[_]
    regex.match(sprintf("(?i)%s", [pattern]), content)
} else {
    regex.match("(?i)/(?:issues?|bugs?|pull|CVE)/.*[0-9]", content)
} else {
    regex.match("(?i)deprecated", content)
}

collect_all_comments(node) = comments {
    comments := {n |
        walk(node, [path, n])
        n.ir_type == "Comment"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := collect_all_comments(parent)[_]
    content := comment.content
    is_suspicious_comment(content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating incomplete security implementation - Comments containing TODO, FIXME, HACK, issue tracker references, deprecated markers, or security-related temporary markers may indicate known deficiencies. (CWE-546)"
    }
}