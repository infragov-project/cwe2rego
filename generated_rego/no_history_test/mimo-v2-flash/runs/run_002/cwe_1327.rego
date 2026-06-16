package glitch

import data.glitch_lib

import future.keywords.in

keyword_names := {"bind_address", "listen_address", "host", "ip_address", "address", "server_bind", "bind_ip", "external_ip", "public_ip", "host_ip", "ip", "bindip", "bindaddress", "listenaddress", "ipaddress", "addr", "bind-address"}
unrestricted_ips := {"0.0.0.0", "::", "all", "any"}

get_string_value(expr) = str {
    expr.ir_type == "String"
    str := expr.value
} else {
    expr.ir_type == "VariableReference"
    str := expr.value
} else {
    str := ""
}

check_key_is_binding(key_expr) {
    key_str := get_string_value(key_expr)
    key_lower := lower(key_str)
    some keyword in keyword_names
    keyword_lower := lower(keyword)
    contains(key_lower, keyword_lower)
}

check_key_string(key_str) {
    key_lower := lower(key_str)
    some keyword in keyword_names
    keyword_lower := lower(keyword)
    contains(key_lower, keyword_lower)
}

check_value_is_unrestricted(value_expr) {
    value_str := get_string_value(value_expr)
    value_lower := lower(value_str)
    some unrestricted in unrestricted_ips
    unrestricted_lower := lower(unrestricted)
    value_lower == unrestricted_lower
}

check_hash_pair_violation(key_expr, value_expr) {
    check_key_is_binding(key_expr)
    check_value_is_unrestricted(value_expr)
}

# Recursively check for hash violations at any depth
check_hash_violation(value_expr) {
    walk(value_expr, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    check_hash_pair_violation(pair.key, pair.value)
}

check_value_violation(value_expr) {
    check_value_is_unrestricted(value_expr)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    check_key_string(attr.name)
    check_value_violation(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    check_hash_violation(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_key_string(var.name)
    check_value_violation(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_hash_violation(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or equivalent addresses. (CWE-1327)"
    }
}