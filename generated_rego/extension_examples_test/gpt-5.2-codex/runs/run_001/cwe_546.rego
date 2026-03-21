package glitch

import data.glitch_lib

task_pattern := "(?i).*\\b(TODO|FIXME|BUGS?|HACK|XXX|LATER2?|TBD|WIP|TEMP)\\b.*"
temp_pattern := "(?i).*(\\btemporary\\b|for[ _-]+testing|quick[ _-]+fix|remove[ _-]+later|\\bwork[-_ ]?around\\b).*"
placeholder_pattern := "(?i).*(\\bhard[-_ ]?coded\\b|\\bdefault[ _-]+password\\b|\\bchange[ _-]+me\\b|\\bplaceholder\\b|replace[ _-]+later).*"
bypass_pattern := "(?i).*(disable[ _-]+auth|skip[ _-]+validation|\\bbypass\\b|no[ _-]+encryption|allow[ _-]+all|open[ _-]+to[ _-]+world).*"
issue_pattern := "(?i).*(https?://[^\\s]*(issue|issues|bug|bugs|ticket|tickets)[^\\s]*|\\b(issue|bug|ticket)s?\\b[^0-9]{0,10}[0-9]{2,}).*"
restriction_pattern := "(?i).*(cannot|can't)\\s+(change|modify|edit|update|remove).*"
warning_pattern := "(?i).*(do not|don't|should not|must not)\\s+(change|modify|edit|update|remove)[^\\n]{0,40}(break|fail|bug|issue|problem).*"
break_pattern := "(?i).*\\bwill\\b[^\\n]{0,20}\\bbreak\\b[^\\n]{0,20}\\b(cookbook|module|role|playbook|recipe|config|configuration|script|system)\\b.*"
deprecated_pattern := "(?i).*\\b(deprecated|deprecate|obsolete|no longer supported)\\b.*"

suspicious_patterns := {task_pattern, temp_pattern, placeholder_pattern, bypass_pattern, issue_pattern, restriction_pattern, warning_pattern, break_pattern, deprecated_pattern}

comment_fields := {"description", "desc", "notes", "note", "annotations", "annotation", "labels", "label", "tags", "tag", "metadata", "documentation", "comment", "comments", "doc"}

suspicious_text(text) {
    p := suspicious_patterns[_]
    regex.match(p, text)
}

name_has_comment_field(name) {
    f := comment_fields[_]
    regex.match(sprintf("(?i).*([^a-z0-9]|^)%s([^a-z0-9]|$).*", [f]), name)
}

suspicious_in_node(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    suspicious_text(n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, c])
    c.ir_type == "Comment"
    suspicious_text(c.content)

    result := {
        "type": "sec_susp_comm",
        "element": c,
        "path": parent.path,
        "description": "Suspicious comment or metadata indicates incomplete or insecure configuration. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_comment_field(attr.name)
    suspicious_in_node(attr.value)

    result := {
        "type": "sec_susp_comm",
        "element": attr,
        "path": parent.path,
        "description": "Suspicious comment or metadata indicates incomplete or insecure configuration. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_has_comment_field(v.name)
    suspicious_in_node(v.value)

    result := {
        "type": "sec_susp_comm",
        "element": v,
        "path": parent.path,
        "description": "Suspicious comment or metadata indicates incomplete or insecure configuration. (CWE-546)"
    }
}