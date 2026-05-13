package glitch

import data.glitch_lib

bind_ip_pattern := "(?i)(bind|listen|ip|address|host|server|source|endpoint|publicly|external|ingress|egress)"
unrestricted_ip_pattern := "^(0\\.0\\.0\\.0|\\*|0\\.0\\.0\\.0/0)$"

normalize_key(key) := k {
    key.ir_type == "VariableReference"
    k := replace(key.value, "^:", "")
} else := k {
    key.ir_type == "String"
    k := replace(key.value, "^:", "")
} else := key.value

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    regex.match(bind_ip_pattern, var.name)
    var.value.ir_type == "String"
    regex.match(unrestricted_ip_pattern, var.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(bind_ip_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(unrestricted_ip_pattern, attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key_name := normalize_key(key)
    regex.match(bind_ip_pattern, key_name)
    value.ir_type == "String"
    regex.match(unrestricted_ip_pattern, value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (CWE-1327)"
    }
}