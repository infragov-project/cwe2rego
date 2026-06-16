package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "passwd", "credential", "admin_password", "db_password", "proxy_password", "key", "token", "activationkey", "secret_key", "api_key", "auth_token", "secret_token"}
connection_string_attrs := {"connection_string", "connectionString", "conn_str", "connection"}

is_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    some keyword
    password_keywords[keyword]
    glitch_lib.contains(node.name, keyword)
    is_empty_password(node.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in variable definition - Variable with empty default value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    some keyword
    password_keywords[keyword]
    glitch_lib.contains(attr.name, keyword)
    is_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords or secrets should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    connection_string_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i).*pwd=\\s*[;\\s].*", attr.value.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string has empty password field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    connection_string_attrs[attr.name]
    is_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string has empty password field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    is_empty_password(var_node.value)
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "mysql_password"
    arg := node.args[_]
    arg.ir_type == "VariableReference"
    arg.value == var_node.name
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in function call - Function call with empty password argument. (CWE-258)"
    }
}