package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node := parent.variables[_]
    regex.match("(?i)(password|secret|token|passphrase|credential|auth|key)", node.name)
    node.value.ir_type == "String"
    node.value.value == ""
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password assigned to a credential field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node := parent.variables[_]
    regex.match("(?i)(password|secret|token|passphrase|credential|auth|key)", node.name)
    node.value.ir_type == "Null"
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Null password assigned to a credential field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)(password|secret|token|passphrase|credential|auth|key)", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == ""
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password assigned to a credential field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)(password|secret|token|passphrase|credential|auth|key)", attr.name)
    attr.value.ir_type == "Null"
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Null password assigned to a credential field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(password|secret|token|passphrase|credential|auth|key)", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == ""
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password assigned to a credential field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(password|secret|token|passphrase|credential|auth|key)", attr.name)
    attr.value.ir_type == "Null"
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Null password assigned to a credential field. (CWE-258)"
    }
}