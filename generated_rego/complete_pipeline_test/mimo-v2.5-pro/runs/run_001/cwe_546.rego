package glitch

import data.glitch_lib

_suspicious_keyword := `(?i)\b(?:TODO|FIXME|HACK|BUG(?:S|GY)?|BROKEN|KLUDGE|XXX|TEMP(?:ORARY|S)?|UNFINISHED|INCOMPLETE|HARDCODED|VULNERABLE|INSECURE|WARNING|WARN|WORKAROUND|DEPRECATED|OBSOLETE|BREAK|UNSUPPORTED)\b`

_issue_tracker_url := `(?i)(?:issues?|bugs?|tickets?|tracker)[/.#]\d+`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    comment.line > 0
    regex.match(_suspicious_keyword, comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating potential security or quality weakness - Suspicious comments suggest unresolved issues, incomplete implementations, or workarounds that must be addressed before production deployment. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    comment.line > 0
    regex.match(_issue_tracker_url, comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating potential security or quality weakness - Comment references an issue tracker or known bug, suggesting deferred fixes or workarounds that may introduce risk if not resolved. (CWE-546)"
    }
}