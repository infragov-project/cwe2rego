package glitch

import data.glitch_lib

suspicious_patterns := {"TODO", "FIXME", "HACK", "BUG", "XXX", "LATER", "HOLD", "TEMP", "WORKAROUND", "OLD", "DEPRECATED", "issues", "tracker", "NOTE", "cannot change", "break the cookbook"}

security_attributes := {"role", "principal", "policy", "permissions", "admin", "ingress", "egress", "cidr_blocks", "firewall_rules", "ports", "encryption", "storage_encrypted", "public_access", "privileged", "root", "security_context", "run_as_user"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    contains_any(comment.content, suspicious_patterns)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    contains_any(comment.content, suspicious_patterns)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_any(attr.name, security_attributes)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment near security attribute (CWE-546)"
    }
}

contains_any(str, patterns) {
    pattern := patterns[_]
    glitch_lib.contains(str, pattern)
}