package glitch

import data.glitch_lib

suspicious_comment_pattern := `(?i)(\btodo\b|\bto-do\b|\bto do\b|\bfixme\b|\bfix-me\b|\bfix me\b|\bbug\b|\bbugfix\b|\bbugme\b|\bdefect\b|\bhack\b|\bkludge\b|\bworkaround\b|\bbandaid\b|\btemp\b|\btemporary\b|\btempfix\b|\bdelete\b|\bremoveme\b|\blater\b|\breview\b|\brevisit\b|\bfollowup\b|\bwarning\b|\bwarn\b|\bcaution\b|\bdanger\b|\bunsafe\b|\bnocommit\b|\bsecurity\b|\binsecure\b|\bvulnerable\b|\bexploit\b|\bbypass\b|\bskipchecks\b|\bhardcoded\b|\bhardcode\b|change this|replace this|do not use in prod|xxx|\?\?\?|!!!|note:)`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Comment"

    regex.match(suspicious_comment_pattern, node.content)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments indicating deferred, incomplete, or insecure configurations that have not been addressed. (CWE-546)"
    }
}