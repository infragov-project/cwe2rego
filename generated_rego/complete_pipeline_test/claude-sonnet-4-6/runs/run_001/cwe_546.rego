package glitch

import data.glitch_lib

keyword_pattern := "(?i)\\b(TODO|FIXME|LATER2?|PENDING|TBD|WIP|INCOMPLETE|PLACEHOLDER|BUGS?|BROKEN|BREAK|DEFECT|HACK|KLUDGE|WORKAROUND|KLUGE|UGLY|TEMP|TEMPORARY|SHORTCUT|BANDAID|INSECURE|VULNERABLE|EXPLOIT|BYPASS|DISABLE|HARDCODED|NO_AUTH|NO_ENCRYPTION|EXPOSED|ALLOW_ALL|PASSWORD|SECRET|TOKEN|CREDENTIAL|API_KEY|ACCESS_KEY|REVIEW|REVISIT|AUDIT|NOSONAR|NOSEC|NOLINT|SUPPRESS|DISABLE_CHECK|SKIP_CHECK|DEPRECATED|NOTE)\\b"

tracker_url_pattern := "(?i)https?://\\S+/issues?/[0-9]+"

is_suspicious(content) {
    regex.match(keyword_pattern, content)
}

is_suspicious(content) {
    regex.match(tracker_url_pattern, content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Comment"
    is_suspicious(node.content)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments may indicate deferred work, known issues, insecure shortcuts, or incomplete security controls in IaC configurations. (CWE-546)"
    }
}