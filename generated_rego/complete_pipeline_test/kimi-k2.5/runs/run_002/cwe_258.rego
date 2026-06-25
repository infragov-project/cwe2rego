package glitch

import data.glitch_lib
import future.keywords.in

credential_patterns := {"password", "passwd", "pwd", "pass", "secret", "secret_key", "secretkey", "api_key", "apikey", "access_key", "accesskey", "auth_token", "token", "credentials", "authentication_key", "master_password", "default_password", "initial_password", "temp_password", "private_key", "password_hash", "passphrase"}

weak_defaults := {"", "changeme", "password", "123456", "admin", "default", "root", "toor", "password123"}

extract_field_name(name) = result {
    parts := split(name, "']['")
    count(parts) > 1
    last := parts[count(parts) - 1]
    result := trim_suffix(trim_prefix(last, "main']['"), "']")
} else = name

is_credential_field(name) {
    field_name := extract_field_name(name)
    lower_name := lower(field_name)
    pattern := credential_patterns[_]
    contains(lower_name, pattern)
    not lower_name == "passwordless"
    not lower_name == "passwords"
    not startswith(lower_name, "no_")
    not endswith(lower_name, "_path")
    not endswith(lower_name, "_file")
    not endswith(lower_name, "_url")
    not endswith(lower_name, "_id")
    not endswith(lower_name, "_hash")
    not contains(lower_name, "nopassword")
    not contains(lower_name, "password_authentication")
    not contains(lower_name, "passwordfile")
}

is_explicit_empty_or_weak(value) {
    value.ir_type == "String"
    count(trim_space(value.value)) == 0
} else {
    value.ir_type == "String"
    lower(value.value) == weak_defaults[_]
    count(value.value) > 0
}

is_value_empty_or_weak(value) {
    is_explicit_empty_or_weak(value)
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

has_definite_value(value) {
    {
        "String": 1,
        "Integer": 1,
        "Float": 1,
        "Boolean": 1,
        "Null": 1,
        "Undef": 1
    }[value.ir_type]
} else {
    value.ir_type == "FunctionCall"
    count(value.args) > 0
    {
        "String": 1,
        "Integer": 1,
        "Float": 1,
        "Boolean": 1,
        "Null": 1,
        "Undef": 1
    }[value.args[0].ir_type]
}

is_class_param_default(block) {
    block.type == "definition"
}

find_var_reference(expr) = vars {
    vars := {node.value |
        walk(expr, [_, node])
        node.ir_type == "VariableReference"
    }
}

is_referencing_empty_var(var_name, all_vars) {
    some var in all_vars
    var.name == var_name
    is_explicit_empty_or_weak(var.value)
}

has_empty_var_reference(expr, all_vars) {
    var_refs := find_var_reference(expr)
    count(var_refs) > 0
    some var_name in var_refs
    is_referencing_empty_var(var_name, all_vars)
}

all_unit_blocks(unit_block) = blocks {
    blocks := {ub |
        walk(unit_block, [_, ub])
        ub.ir_type == "UnitBlock"
    }
}

collect_all_vars(unit_block) = all_vars {
    direct := {v | v := unit_block.variables[_]}
    nested := {v |
        nested_b := unit_block.unit_blocks[_]
        v := nested_b.variables[_]
    }
    all_vars := direct | nested
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    is_credential_field(var.name)
    is_explicit_empty_or_weak(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty or weak password in configuration file - Password fields should not be empty, null, or use common default values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "KeyValue"
    is_credential_field(node.name)
    is_explicit_empty_or_weak(node.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty or weak password in configuration file - Password fields should not be empty, null, or use common default values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nested_blocks := all_unit_blocks(parent)
    nested := nested_blocks[_]
    nested != parent
    
    attr := nested.attributes[_]
    is_credential_field(attr.name)
    is_value_empty_or_weak(attr.value)
    not is_class_param_default(nested)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty or weak password in configuration file - Password attribute should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := collect_all_vars(parent)
    count(all_vars) > 0
    
    walk(parent, [path, node])
    
    node.ir_type == "KeyValue"
    is_credential_field(node.name)
    not is_value_empty_or_weak(node.value)
    has_definite_value(node.value)
    has_empty_var_reference(node.value, all_vars)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password field references variable with empty/null value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := collect_all_vars(parent)
    count(all_vars) > 0
    
    nested_blocks := all_unit_blocks(parent)
    nested := nested_blocks[_]
    nested != parent
    
    attr := nested.attributes[_]
    is_credential_field(attr.name)
    not is_value_empty_or_weak(attr.value)
    has_definite_value(attr.value)
    has_empty_var_reference(attr.value, all_vars)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password attribute references variable with empty/null value. (CWE-258)"
    }
}