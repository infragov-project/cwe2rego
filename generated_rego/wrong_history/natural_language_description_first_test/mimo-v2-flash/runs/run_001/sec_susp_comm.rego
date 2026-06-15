package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "HACK", "FIXME", "BUG", "INSECURE", "NOTE", "TEMPORARY", "WORKAROUND", "BREAK", "CANNOT", "CHANGE", "DEPRECATED", "ISSUE", "TRACKER"}

has_suspicious_keyword(text) {
    kw := suspicious_keywords[_]
    glitch_lib.contains(text, kw)
}

security_attrs := {"permission", "access", "secret", "key", "credential", "auth", "security", "encryption", "network", "firewall", "role", "policy"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    has_suspicious_keyword(comment.content)

    atomic_unit := parent.atomic_units[_]
    attr := atomic_unit.attributes[_]
    security_attrs[attr.name]

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious keyword in comment near security-sensitive configuration. This may indicate a temporary or insecure fix that could introduce vulnerabilities. (CWE-710)"
    }
}