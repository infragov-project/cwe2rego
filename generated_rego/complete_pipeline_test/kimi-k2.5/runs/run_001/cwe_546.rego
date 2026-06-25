package glitch

import data.glitch_lib

actionable_markers := {"TODO", "FIXME", "XXX", "HACK", "TEMP", "TEMPORARY", "FUTURE", "PENDING", "POSTPONED", "DEFER", "DEFERRED", "WORKAROUND", "BROKEN", "FRAGILE", "REFACTOR", "CLEANUP", "DEPRECATED", "DEPRECATE", "OBSOLETE", "REMOVE", "DELETE", "NOTE", "BREAK"}

issue_tracker_pattern := "(issues?|bugs?|tickets?)[/=\\-_]?\\d+|github\\.com/.*/issues/\\d+|tracker\\.[\\w\\.]+/(issues|r)/\\d+"

has_actionable_marker(content) {
    marker := actionable_markers[_]
    regex.match(sprintf("(?i)\\b%s\\b", [marker]), content)
}

has_issue_tracker_reference(content) {
    regex.match(sprintf("(?i)%s", [issue_tracker_pattern]), content)
}

indicates_breakage_or_limitation(content) {
    regex.match("(?i)(breaks?\\b|broken\\b|cannot\\b|can't\\b|unable\\b|not possible\\b|doesn't work\\b|won't work\\b|workaround\\b|limitation\\b|only works\\b|not supported\\b|does not work\\b)", content)
}

is_suspicious_content(content) {
    has_actionable_marker(content)
} else {
    has_issue_tracker_reference(content)
} else {
    indicates_breakage_or_limitation(content)
}

is_license_excluded(content) {
    regex.match("(?i)^\\s*#?\\s*(copyright|license|apache|mit|gpl|@license|@author|source:)", content)
}

is_license_text(content) {
    regex.match("(?i)(licensed under|limitations under|permission of|warranties or conditions|is distributed|see the license|apache license)", content)
}

is_excluded(content) {
    is_license_excluded(content)
} else {
    is_license_text(content)
}

is_suspicious(content) {
    is_suspicious_content(content)
    not is_excluded(content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    content := comment.content
    content != ""
    is_suspicious(content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comment indicates incomplete implementation, known limitation, issue tracker reference, or deferred work that may have security implications. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [path, node] := walk(parent)
    node.ir_type == "String"
    code := node.code
    code != ""
    contains(code, "#")
    extracted := regex.find_all_string_submatch_n("#[^\\n]+", code, -1)[0][0]
    is_suspicious(extracted)
    result := {
        "type": "sec_susp_comm",
        "element": {
            "ir_type": "Comment",
            "line": node.line,
            "column": node.column,
            "end_line": node.end_line,
            "end_column": node.end_column,
            "code": extracted,
            "content": extracted
        },
        "path": parent.path,
        "description": "Suspicious comment detected - Embedded comment indicates incomplete implementation, known limitation, issue tracker reference, or deferred work. (CWE-546)"
    }
}