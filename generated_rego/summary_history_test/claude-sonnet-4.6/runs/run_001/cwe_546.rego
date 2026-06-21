package glitch

import data.glitch_lib

suspicious_comment_pattern := "(?i).*(TODO|FIXME|LATER|TBD|INCOMPLETE|PLACEHOLDER|STUB|WIP|REVISIT|PENDING|BUG|DEFECT|BROKEN|BREAK|DEPRECATED|HACK|KLUDGE|WORKAROUND|TEMP|TEMPORARY|SUPPRESS|BYPASS|INSECURE|UNSAFE|VULNERABLE|SECURITY|HARDCODED|PASSWORD|SECRET|TOKEN|CREDENTIAL|DISABLED|EXPLOIT|CVE-|CWE-|NOTE|/issues/).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, comment])
    comment.ir_type == "Comment"

    regex.match(suspicious_comment_pattern, comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected in IaC script - Comments may indicate deferred security decisions, known vulnerabilities, incomplete configurations, or disabled security controls. (CWE-546)"
    }
}