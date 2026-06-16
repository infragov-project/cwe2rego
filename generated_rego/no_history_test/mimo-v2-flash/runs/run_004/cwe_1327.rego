package glitch

import data.glitch_lib

binding_attr_pattern := "(?i)(bind[_-]?address|listen[_-]?address|host|address|ip_address|server_address|ip|bind|listen|addr)"

check_key_pattern(key_expr) {
    key_expr.ir_type == "VariableReference"
    regex.match(binding_attr_pattern, key_expr.value)
} else {
    key_expr.ir_type == "String"
    regex.match(binding_attr_pattern, key_expr.value)
}

check_value_is_unrestricted(value_expr) {
    value_expr.ir_type == "String"
    value_expr.value == "0.0.0.0"
} else {
    value_expr.ir_type == "VariableReference"
    value_expr.value == "0.0.0.0"
}

find_and_check_hashes(node, path, parent_path) = result {
    node.ir_type == "Hash"
    pair := node.value[_]
    check_key_pattern(pair.key)
    check_value_is_unrestricted(pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent_path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This allows unrestricted access and may lead to unauthorized access or DoS attacks. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(binding_attr_pattern, node.name)
    check_value_is_unrestricted(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This allows unrestricted access and may lead to unauthorized access or DoS attacks. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(binding_attr_pattern, node.name)
    check_value_is_unrestricted(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This allows unrestricted access and may lead to unauthorized access or DoS attacks. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    result := find_and_check_hashes(node, path, parent.path)
    result != null
}