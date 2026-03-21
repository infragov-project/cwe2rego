package glitch

import data.glitch_lib

binding_name_pattern := "(?i).*(listen|bind|addr|address|host|ip).*"

is_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
}

key_matches_binding(key) {
    key.ir_type == "String"
    regex.match(binding_name_pattern, key.value)
}

key_matches_binding(key) {
    key.ir_type == "VariableReference"
    regex.match(binding_name_pattern, key.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(binding_name_pattern, attr.name)
    is_unrestricted_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The address 0.0.0.0 exposes the server to every possible network. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(binding_name_pattern, var.name)
    is_unrestricted_ip(var.value)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The address 0.0.0.0 exposes the server to every possible network. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_matches_binding(entry.key)
    is_unrestricted_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The address 0.0.0.0 exposes the server to every possible network. (CWE-1327)"
    }
}