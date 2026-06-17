package glitch

import data.glitch_lib

binding_keywords := {"listen", "bind", "address", "ip", "host", "server", "interface", "public", "expose", "access", "security", "firewall", "conf"}
unrestricted_values := {"0.0.0.0", "*", "all interfaces", "any ip", "0.0.0.0/0"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    name_lower := lower(var.name)
    contains_any(name_lower, binding_keywords)
    
    var.value.ir_type == "String"
    value_lower := lower(var.value.value)
    unrestricted_values[value_lower]
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address (0.0.0.0) - This may allow remote connections from any IP. (CWE-1327)"
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
    
    key_name := key.value
    key_name_lower := lower(key_name)
    contains_any(key_name_lower, binding_keywords)
    
    value.ir_type == "String"
    value_lower := lower(value.value)
    unrestricted_values[value_lower]
    
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address (0.0.0.0) - This may allow remote connections from any IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attrs := atomic_unit.attributes
    attr := attrs[_]
    
    name_lower := lower(attr.name)
    contains_any(name_lower, binding_keywords)
    
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    unrestricted_values[value_lower]
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address (0.0.0.0) - This may allow remote connections from any IP. (CWE-1327)"
    }
}

contains_any(str, keywords) {
    keyword := keywords[_]
    contains(str, keyword)
}

contains(str, substr) {
    normalized_str := replace(replace(str, "-", ""), "_", "")
    normalized_substr := replace(replace(substr, "-", ""), "_", "")
    regex.match(sprintf("(?i).*%s.*", [normalized_substr]), normalized_str)
}