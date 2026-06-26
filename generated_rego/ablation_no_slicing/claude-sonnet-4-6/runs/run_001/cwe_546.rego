package glitch

import data.glitch_lib

suspicious_comment_pattern := "(?i).*(\\btodo\\b|\\bfixme\\b|\\bhack\\b|\\bbug\\b|\\bkludge\\b|\\bxxx\\b|\\bnosonar\\b|\\bbypass\\b|\\binsecure\\b|\\bunsafe\\b|hardcoded|hard-coded|\\bplaceholder\\b|change this|replace me|default password|test credential|\\bdummy\\b|too permissive|wide open|allow all|open access|\\bunrestricted\\b|\\bvulnerable\\b|\\bexploitable\\b|\\bdangerous\\b|known issue|\\bcve\\b|not safe|security issue|remove before production|disabled for now|open for testing|skip validation|not secure|\\bdeprecated\\b|\\brevisit\\b|\\bworkaround\\b|\\btemp\\b|\\btemporary\\b|/issues/[0-9]).*"

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "UnitBlock"
    node.path != ""
    comment := node.comments[_]
    regex.match(suspicious_comment_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": node.path,
        "description": "Suspicious comment detected - Comments suggest deferred, disabled, or incomplete security controls in infrastructure code. (CWE-546)"
    }
}