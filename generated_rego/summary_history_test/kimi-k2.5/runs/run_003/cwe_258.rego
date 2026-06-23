package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "pwd", "secret", "credential", "auth_token", "api_key", "access_key", "secret_key", "private_key", "token", "admin_password", "root_password", "master_password", "connection_password", "database_password", "service_account_key", "client_secret", "activation_key", "ssh_password"}

is_sensitive_key(name) {
    lower_name := lower(name)
    kw := password_keywords[_]
    contains(lower_name, kw)
}

contains(str, substr) {
    regex.match(sprintf(".*%s.*", [substr]), str)
}

is_empty_or_null_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_or_null_value(value) {
    value.ir_type == "String"
    regex.match("^[\\s]+$", value.value)
}

is_empty_or_null_value(value) {
    value.ir_type == "Null"
}

is_empty_or_null_value(value) {
    value.ir_type == "Undef"
}

find_in_hash_or_array(parent, target_name) {
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    is_sensitive_key(node.name)
    is_empty_or_null_value(node.value)
}

all_values(node) = values {
    values = {n |
        walk(node, [_, n])
        n.ir_type == "String"
    } | {n |
        walk(node, [_, n])
        n.ir_type == "Null"
    } | {n |
        walk(node, [_, n])
        n.ir_type == "Undef"
    } | {n |
        walk(node, [_, n])
        n.ir_type == "Hash"
    } | {n |
        walk(node, [_, n])
        n.ir_type == "Array"
    } | {n |
        walk(node, [_, n])
        n.ir_type == "VariableReference"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_sensitive_key(var.name)
    is_empty_or_null_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    is_sensitive_key(attr.name)
    is_empty_or_null_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_sensitive_key(attr.name)
    is_empty_or_null_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    nested_attrs := {n |
        walk(au, [_, n])
        n.ir_type == "Attribute"
        n.value.ir_type == "Hash"
    }
    
    attr := nested_attrs[_]
    walk(attr.value, [_, kv])
    kv.ir_type == "KeyValue"
    is_sensitive_key(kv.name)
    is_empty_or_null_value(kv.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    nested_attrs := {n |
        walk(au, [_, n])
        n.ir_type == "Attribute"
        n.value.ir_type == "Array"
    }
    
    attr := nested_attrs[_]
    walk(attr.value, [_, elem])
    elem.ir_type == "KeyValue"
    is_sensitive_key(elem.name)
    is_empty_or_null_value(elem.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": elem,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}

variable_has_empty_or_null_value(root, var_name) {
    walk(root, [_, node])
    node.ir_type == "Variable"
    node.name == var_name
    is_empty_or_null_value(node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    
    arg := fc.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    
    is_sensitive_key(var_name)
    variable_has_empty_or_null_value(input, var_name)
    
    result := {
        "type": "sec_empty_pass",
        "element": arg,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, mc])
    mc.ir_type == "MethodCall"
    
    arg := mc.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    
    is_sensitive_key(var_name)
    variable_has_empty_or_null_value(input, var_name)
    
    result := {
        "type": "sec_empty_pass",
        "element": arg,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not have empty values. (CWE-258)"
    }
}