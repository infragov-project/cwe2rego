package glitch

import data.glitch_lib

unrestricted_ips := {"0.0.0.0", "::"}

binding_keywords := {"bind", "listen", "ip", "address", "host", "server", "bind-address", "listenaddr", "bindip", "bind_address", "listen_address"}

contains_binding_keyword(str) {
    keyword := binding_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), str)
}

get_string_value(node) = str {
    node.ir_type == "String"
    str := node.value
} else {
    node.ir_type == "VariableReference"
    str := node.value
} else {
    node.ir_type == "Integer"
    str := sprintf("%d", [node.value])
} else {
    str := ""
}

# Check if a node contains unrestricted IP binding in its attributes or hash values
check_unrestricted_binding(node, parent_path) = results {
    results := {result |
        # Check attributes directly
        attr := glitch_lib.all_attributes(node)[_]
        key_str := attr.name
        value_str := get_string_value(attr.value)
        contains_binding_keyword(key_str)
        unrestricted_ips[value_str]
        result := {
            "type": "sec_invalid_bind",
            "element": attr,
            "path": parent_path,
            "description": "Unrestricted IP binding - The service is bound to an unrestricted IP address (0.0.0.0 or ::), which may allow unintended remote access. (CWE-1327)"
        }
    }
} else = results {
    # Check hash values recursively
    results := {result |
        walk(node, [path, n])
        n.ir_type == "Hash"
        pair := n.value[_]
        key_str := get_string_value(pair.key)
        value_str := get_string_value(pair.value)
        contains_binding_keyword(key_str)
        unrestricted_ips[value_str]
        result := {
            "type": "sec_invalid_bind",
            "element": pair.key,
            "path": parent_path,
            "description": "Unrestricted IP binding - The service is bound to an unrestricted IP address (0.0.0.0 or ::), which may allow unintended remote access. (CWE-1327)"
        }
    }
}

# Rule for Variables containing unrestricted IP bindings (including in hash values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    
    results := check_unrestricted_binding(node, parent.path)
    result := results[_]
}

# Rule for Attributes containing unrestricted IP bindings (including in hash values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    
    results := check_unrestricted_binding(node, parent.path)
    result := results[_]
}

# Rule for AtomicUnits containing unrestricted IP bindings (e.g., resource definitions)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    results := check_unrestricted_binding(node, parent.path)
    result := results[_]
}