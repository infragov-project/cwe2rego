package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "FIXME", "BUG", "HACK", "WORKAROUND", "TEMPORARY", "INSECURE", "UNSAFE", "VULNERABLE", "NOTE", "cannot change", "break the"}
remediation_tags := {"RESOLVED", "VERIFIED", "SECURITY-REVIEWED", "SECURE", "RESOLVED:", "VERIFIED:"}

contains_suspicious_without_remediation(str) {
    kw := suspicious_keywords[_]
    glitch_lib.contains(str, kw)
    not remediation_tag_present(str)
}

remediation_tag_present(str) {
    tag := remediation_tags[_]
    glitch_lib.contains(str, tag)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    contains_suspicious_without_remediation(comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious keyword in comment without remediation tag."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_unit := glitch_lib.all_atomic_units(parent)[_]
    contains_suspicious_without_remediation(atomic_unit.code)
    result := {
        "type": "sec_susp_comm",
        "element": atomic_unit,
        "path": parent.path,
        "description": "Suspicious keyword in atomic unit code without remediation tag."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    attr.value.ir_type == "String"
    contains_suspicious_without_remediation(attr.value.value)
    result := {
        "type": "sec_susp_comm",
        "element": attr,
        "path": parent.path,
        "description": "Suspicious keyword in attribute value without remediation tag."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    var.value.ir_type == "String"
    contains_suspicious_without_remediation(var.value.value)
    result := {
        "type": "sec_susp_comm",
        "element": var,
        "path": parent.path,
        "description": "Suspicious keyword in variable value without remediation tag."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    contains_suspicious_without_remediation(comment.code)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious keyword in comment code without remediation tag."
    }
}