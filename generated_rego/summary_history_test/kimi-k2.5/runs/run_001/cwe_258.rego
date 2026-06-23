package glitch

import data.glitch_lib
import future.keywords.in

weak_passwords := {"password", "admin", "123456", "changeme", "default", "guest", "user", "test", "login", "qwerty", "letmein", "welcome", "pass", "secret", "root", "toor", "ansible", "puppet", "chef", "vagrant", "docker"}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_weak_password(value) {
    value.ir_type == "String"
    weak_passwords[lower(value.value)]
} else {
    value.ir_type == "String"
    regex.match("^(?i)(pass|pwd|secret|admin|test|default|root|login)[0-9!@#$%^&*]*$", value.value)
}

is_credential_field(name) {
    password_patterns := {"password", "passwd", "pwd", "pass", "secret", "secret_key", "secretkey", "auth_token", "authtoken", "token", "credentials", "creds", "access_key", "accesskey", "private_key", "privatekey", "admin_password", "root_password", "db_password", "database_password", "mysql_password", "postgres_password", "activationkey", "activation_key"}
    some pattern in password_patterns
    regex.match(sprintf("(?i).*\\b%s\\b.*", [pattern]), name)
}

get_string_from_key(key) = str {
    key.ir_type == "String"
    str = key.value
} else = str {
    key.ir_type == "VariableReference"
    str = key.value
} else = str {
    str = sprintf("%v", [key])
}

check_hash_for_empty_creds(hash, base_path, parent_path, r) {
    some pair in hash.value
    key_str := get_string_from_key(pair[0])
    field_path := array.concat(base_path, [key_str])
    full_name := concat("", field_path)
    is_credential_field(full_name)
    is_empty_value(pair[1])
    r := {
        "type": "sec_empty_pass",
        "element": pair[1],
        "path": parent_path,
        "description": sprintf("Empty password in hash field '%s' - Credential fields should not be set to empty or null values. (CWE-258)", [full_name])
    }
}

check_hash_for_weak_creds(hash, base_path, parent_path, r) {
    some pair in hash.value
    key_str := get_string_from_key(pair[0])
    field_path := array.concat(base_path, [key_str])
    full_name := concat("", field_path)
    is_credential_field(full_name)
    is_weak_password(pair[1])
    r := {
        "type": "sec_empty_pass",
        "element": pair[1],
        "path": parent_path,
        "description": sprintf("Weak hardcoded password in hash field '%s' - Credential fields should not use weak or default passwords. (CWE-521)", [full_name])
    }
}

has_variable_reference(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_var in parent.variables
    is_credential_field(any_var.name)
    is_empty_value(any_var.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_var,
        "path": parent.path,
        "description": "Empty password in configuration - Credential variables should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_var in parent.variables
    any_var.value.ir_type == "Hash"
    r := check_hash_for_empty_creds(any_var.value, [any_var.name], parent.path, _)
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_attr in parent.attributes
    is_credential_field(any_attr.name)
    is_empty_value(any_attr.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_attr,
        "path": parent.path,
        "description": "Empty password in configuration - Credential fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_attr in parent.attributes
    any_attr.value.ir_type == "Hash"
    r := check_hash_for_empty_creds(any_attr.value, [any_attr.name], parent.path, _)
}

Glitch_Analysis[r] {
    blocks := {n | [_, n] := walk(parent); n.ir_type == "UnitBlock"}
    some block in blocks
    block.path != ""

    some any_var in block.variables
    is_credential_field(any_var.name)
    is_empty_value(any_var.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_var,
        "path": block.path,
        "description": "Empty password in nested block - Credential variables should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[r] {
    blocks := {n | [_, n] := walk(parent); n.ir_type == "UnitBlock"}
    some block in blocks
    block.path != ""

    some any_attr in block.attributes
    is_credential_field(any_attr.name)
    is_empty_value(any_attr.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_attr,
        "path": block.path,
        "description": "Empty password in nested block attribute - Credential fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some node in atomic_units
    some any_attr in node.attributes
    is_credential_field(any_attr.name)
    is_empty_value(any_attr.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_attr,
        "path": parent.path,
        "description": "Empty password in atomic unit - Credential fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some node in atomic_units
    some any_attr in node.attributes
    any_attr.value.ir_type == "Hash"
    r := check_hash_for_empty_creds(any_attr.value, [any_attr.name], parent.path, _)
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_var in parent.variables
    is_credential_field(any_var.name)
    is_weak_password(any_var.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_var,
        "path": parent.path,
        "description": "Weak hardcoded password - Credential variables should not use weak or default passwords. (CWE-521)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_var in parent.variables
    any_var.value.ir_type == "Hash"
    r := check_hash_for_weak_creds(any_var.value, [any_var.name], parent.path, _)
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_attr in parent.attributes
    is_credential_field(any_attr.name)
    is_weak_password(any_attr.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_attr,
        "path": parent.path,
        "description": "Weak hardcoded password - Credential fields should not use weak or default passwords. (CWE-521)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some any_attr in parent.attributes
    any_attr.value.ir_type == "Hash"
    r := check_hash_for_weak_creds(any_attr.value, [any_attr.name], parent.path, _)
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some node in atomic_units
    some any_attr in node.attributes
    is_credential_field(any_attr.name)
    is_weak_password(any_attr.value)
    
    r := {
        "type": "sec_empty_pass",
        "element": any_attr,
        "path": parent.path,
        "description": "Weak hardcoded password in atomic unit - Credential fields should not use weak or default passwords. (CWE-521)"
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    some node in atomic_units
    some any_attr in node.attributes
    any_attr.value.ir_type == "Hash"
    r := check_hash_for_weak_creds(any_attr.value, [any_attr.name], parent.path, _)
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, anything] := walk(parent)
    anything.ir_type == "FunctionCall"
    func_name := lower(anything.name)
    func_patterns := {"password", "secret", "token", "auth", "credential"}
    some fp in func_patterns
    contains(func_name, fp)
    some arg in anything.args
    is_empty_value(arg)
    
    r := {
        "type": "sec_empty_pass",
        "element": arg,
        "path": parent.path,
        "description": sprintf("Empty password passed to %s function - Credential functions should not receive empty values. (CWE-258)", [anything.name])
    }
}

Glitch_Analysis[r] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, anything] := walk(parent)
    anything.ir_type == "FunctionCall"
    func_name := lower(anything.name)
    func_patterns := {"password", "secret", "token", "auth", "credential"}
    some fp in func_patterns
    contains(func_name, fp)
    some arg in anything.args
    is_weak_password(arg)
    
    r := {
        "type": "sec_empty_pass",
        "element": arg,
        "path": parent.path,
        "description": sprintf("Weak password passed to %s function - Credential functions should not receive weak passwords. (CWE-521)", [anything.name])
    }
}