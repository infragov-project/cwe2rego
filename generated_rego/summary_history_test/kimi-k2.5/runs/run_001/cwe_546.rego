package glitch

import data.glitch_lib
import future.keywords.if
import future.keywords.in

suspicious_keywords := {
    "bug", "known-issue", "known issue", "issue", "defect", "glitch", "workaround",
    "fixme", "fix-me", "todo", "to-do", "xxx", "hack", "temp", "temporary",
    "later", "later2", "pending", "deferred", "future", "next-release", "backlog",
    "insecure", "broken-auth", "broken auth", "bypass-needed", "bypass needed",
    "disabled-security", "disabled security", "weak-crypto", "weak crypto",
    "hardcoded", "hard coded",
    "review-needed", "review needed", "revisit", "question", "confirm", "verify",
    "not-sure", "not sure", "unsure",
    "quick-fix", "quick fix", "band-aid", "bandaid", "stopgap", "kludge", "ugly", "dirty"
}

security_context_keywords := {
    "auth", "authentication", "authorization", "encrypt", "encryption",
    "ssl", "tls", "certificate", "password", "secret", "credential",
    "firewall", "network", "input", "validation", "sanitize", "log",
    "monitor", "audit", "backdoor", "exploit", "vulnerability"
}

has_security_context(content) if {
    some ctx in security_context_keywords
    regex.match(sprintf(".*(?:^|[^a-zA-Z0-9_-])%s(?:[^a-zA-Z0-9_-]|$).*", [ctx]), content)
}

matches_suspicious(content, keyword) if {
    lower_content := lower(content)
    regex.match(sprintf(".*(?:^|[^a-zA-Z0-9_-])%s(?:[^a-zA-Z0-9_-]|$).*", [keyword]), lower_content)
}

get_severity(content) = "high" if {
    has_security_context(lower(content))
}

get_severity(content) = "medium" if {
    not has_security_context(lower(content))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some comment in parent.comments
    some keyword in suspicious_keywords
    matches_suspicious(comment.content, keyword)
    severity := get_severity(comment.content)
    result := {
        "type": sprintf("sec_suspicious_comment_%s", [severity]),
        "element": comment,
        "path": parent.path,
        "description": sprintf("Suspicious comment detected: contains '%s' indicating incomplete/temporary implementation. (CWE-546)", [keyword])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some node in atomic_units
    some attr in node.attributes
    attr.code != ""
    some keyword in suspicious_keywords
    matches_suspicious(attr.code, keyword)
    severity := get_severity(attr.code)
    result := {
        "type": sprintf("sec_suspicious_comment_%s", [severity]),
        "element": attr,
        "path": parent.path,
        "description": sprintf("Suspicious comment in attribute '%s': contains '%s' indicating incomplete/temporary implementation. (CWE-546)", [attr.name, keyword])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in parent.variables
    var.code != ""
    some keyword in suspicious_keywords
    matches_suspicious(var.code, keyword)
    severity := get_severity(var.code)
    result := {
        "type": sprintf("sec_suspicious_comment_%s", [severity]),
        "element": var,
        "path": parent.path,
        "description": sprintf("Suspicious comment in variable '%s': contains '%s' indicating incomplete/temporary implementation. (CWE-546)", [var.name, keyword])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some node in atomic_units
    node.code != ""
    some keyword in suspicious_keywords
    matches_suspicious(node.code, keyword)
    severity := get_severity(node.code)
    result := {
        "type": sprintf("sec_suspicious_comment_%s", [severity]),
        "element": node,
        "path": parent.path,
        "description": sprintf("Suspicious comment in atomic unit '%s': contains '%s' indicating incomplete/temporary implementation. (CWE-546)", [node.type, keyword])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some nested in parent.unit_blocks
    some comment in nested.comments
    some keyword in suspicious_keywords
    matches_suspicious(comment.content, keyword)
    severity := get_severity(comment.content)
    result := {
        "type": sprintf("sec_suspicious_comment_%s", [severity]),
        "element": comment,
        "path": parent.path,
        "description": sprintf("Suspicious comment in nested block '%s': contains '%s' indicating incomplete/temporary implementation. (CWE-546)", [nested.name, keyword])
    }
}