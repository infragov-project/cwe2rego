package glitch

import data.glitch_lib

binding_indicators := {"bind", "listen", "ip", "address", "host", "interface", "server", "bind_address", "listen_address", "ip_address", "server_ip", "server_address", "bind_ip"}
unrestricted_values := {"0.0.0.0", "*", "0.0.0.0/0", "any"}

check_key_name(key_expr) = true {
    key_expr.ir_type == "String"
    key_str := lower(key_expr.value)
    contains_binding_indicator(key_str)
} else {
    key_expr.ir_type == "VariableReference"
    key_str := lower(regex.replace(key_expr.value, "^:", ""))
    contains_binding_indicator(key_str)
}

contains_binding_indicator(key_str) = true {
    indicator := binding_indicators[_]
    regex.match(sprintf("(?i).*%s.*", [indicator]), key_str)
}

check_value(value_expr) = true {
    value_expr.ir_type == "String"
    value_str := value_expr.value
    unrestricted_values[_] == value_str
}

check_key_name_string(name) = true {
    name_str := lower(name)
    contains_binding_indicator(name_str)
}

get_binding_hash_pairs(hash_expr) = pairs {
    hash_expr.ir_type == "Hash"
    pairs := {pair |
        walk(hash_expr, [path, node])
        node.ir_type == "Hash"
        h_pair := node.value[_]
        check_key_name(h_pair.key)
        check_value(h_pair.value)
        pair := h_pair
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    check_key_name_string(variable.name)
    check_value(variable.value)
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to an unrestricted IP address (0.0.0.0, *, etc.), which may allow unintended network access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    check_key_name_string(attribute.name)
    check_value(attribute.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attribute,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to an unrestricted IP address (0.0.0.0, *, etc.), which may allow unintended network access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    variable.value.ir_type == "Hash"
    pairs := get_binding_hash_pairs(variable.value)
    pair := pairs[_]
    result := {
        "type": "sec_invalid_bind",
        "element": pair.key,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to an unrestricted IP address (0.0.0.0, *, etc.), which may allow unintended network access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    attribute.value.ir_type == "Hash"
    pairs := get_binding_hash_pairs(attribute.value)
    pair := pairs[_]
    result := {
        "type": "sec_invalid_bind",
        "element": pair.key,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to an unrestricted IP address (0.0.0.0, *, etc.), which may allow unintended network access. (CWE-1327)"
    }
}