package glitch

import data.glitch_lib

suspicious_comment_pattern := "(?i)(\\b(TODO|FIXME|LATER2?|TBD|PENDING|INCOMPLETE|BUG|HACK|KLUDGE|KLUGE|XXX|WORKAROUND|BROKEN|NOTE|deprecated)\\b|https?://\\S+/issues/\\d+|\\b(temporary|insecure|disabled|bypassed|unrestricted|vulnerable|weakness|dangerous|risky|placeholder|dummy)\\b|hard[\\s-]?coded|not[\\s-]?secure|allow[\\s-]?all|not[\\s-]?for[\\s-]?prod|testing[\\s-]?only|dev[\\s-]?only|change[\\s]+this|replace[\\s]+this|update[\\s]+this|remove[\\s]+before|delete[\\s]+before)"

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
        "description": "Suspicious comment detected - May indicate unresolved security issues, deferred security configurations, or bypassed security controls. (CWE-546)"
    }
}