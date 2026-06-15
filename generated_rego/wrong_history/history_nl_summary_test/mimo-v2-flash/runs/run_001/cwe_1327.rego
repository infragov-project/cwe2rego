package glitch

import data.glitch_lib

binding_pattern := "(?i).*(bind|ip|address|host|listen|server|net).*"

get_key_name(key) = name {
    key.ir_type == "VariableReference"
    name := trim_prefix(key.value, ":")
} else = name {
    key.ir_type == "String"
    name := key.value
} else = name {
    name := key.code
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    count(path) >= 2
    parent_path := array.slice(path, 0, count(path) - 2)
    walk(parent, [parent_path, hash_node])
    hash_node.ir_type == "Hash"
    
    pair := hash_node.value[_]
    pair.value == node
    
    key_name := get_key_name(pair.key)
    regex.match(binding_pattern, key_name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This violates the principle of least privilege. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    variable.value.ir_type == "String"
    variable.value.value == "0.0.0.0"
    
    regex.match(binding_pattern, variable.name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": variable.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This violates the principle of least privilege. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    
    attribute.value.ir_type == "String"
    attribute.value.value == "0.0.0.0"
    
    regex.match(binding_pattern, attribute.name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attribute.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This violates the principle of least privilege. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.value.ir_type == "String"
    pair.value.value == "0.0.0.0"
    key_name := get_key_name(pair.key)
    regex.match(binding_pattern, key_name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This violates the principle of least privilege. (CWE-1327)"
    }
}