package glitch

import data.glitch_lib

binding_name_pattern := `(?i).*(bind|listen|addr(ress)?|_ip|:ip|host|interface|socket).*`

wildcard_ip_pattern := `^(0\.0\.0\.0(/0)?|::|::0|0:0:0:0:0:0:0:0|::/0|\*)$`

is_binding_name(name) {
    regex.match(binding_name_pattern, name)
}

is_wildcard_ip(value) {
    value.ir_type == "String"
    regex.match(wildcard_ip_pattern, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_binding_name(variable.name)
    is_wildcard_ip(variable.value)
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is bound to all interfaces (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_name(attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is bound to all interfaces (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_name := entry.key.value
    is_binding_name(key_name)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is bound to all interfaces (CWE-1327)"
    }
}