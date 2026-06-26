package glitch

import data.glitch_lib

binding_name_pattern := "(?i).*(listen|bind|host|address|addr|ip).*"

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
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The product assigns the address 0.0.0.0, which allows connections from every IP address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(binding_name_pattern, v.name)
    v.value.ir_type == "String"
    v.value.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The product assigns the address 0.0.0.0, which allows connections from every IP address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    entry := hash.value[_]
    key_matches_binding(entry.key)
    entry.value.ir_type == "String"
    entry.value.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The product assigns the address 0.0.0.0, which allows connections from every IP address. (CWE-1327)"
    }
}