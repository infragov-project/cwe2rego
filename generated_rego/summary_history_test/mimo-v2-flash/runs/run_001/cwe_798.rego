package glitch

import data.glitch_lib

sensitive_credential_keywords := {"password", "secret", "token", "api_key", "private_key", "credential", "auth_token", "access_key", "secret_key", "admin_password", "master_password", "db_password", "master_user_password", "root_password", "connection_string", "bearer_token", "ssh_private_key", "encryption_key", "admin_login", "master_username", "service_principal_password", "client_secret", "kubeconfig", "access_key_id", "secret_access_key", "sha512_password"}

contextual_keywords := {"user", "key", "credential", "auth", "login", "token", "secret"}

placeholders := {"admin", "changeme", "password123", "123456", "example_token", "default", "test", "telarista", "redhat1", "sensu", "root", "administrator"}

is_base64(str) {
    regex.match("^[A-Za-z0-9+/]*={0,2}$", str)
    count(str) >= 20
}

is_placeholder(str) {
    lower_str := lower(str)
    placeholder := placeholders[_]
    lower_str == placeholder
}

is_password_hash(str) {
    regex.match("^\\$[0-9]\\$", str)
}

contains_credential_keyword(name) {
    lower_name := lower(name)
    keyword := sensitive_credential_keywords[_]
    contains(lower_name, keyword)
}

contains_contextual_keyword(name) {
    lower_name := lower(name)
    keyword := contextual_keywords[_]
    contains(lower_name, keyword)
}

is_credential_context(name, value) {
    contains_credential_keyword(name)
    value.ir_type == "String"
    value.value != ""
    not glitch_lib.traverse_var(value)
}

is_contextual_credential(name, value) {
    contains_contextual_keyword(name)
    value.ir_type == "String"
    value.value != ""
    any([is_placeholder(value.value), is_base64(value.value), is_password_hash(value.value)])
    not glitch_lib.traverse_var(value)
}

is_credential_pair(key, value) {
    is_credential_context(key, value)
}

is_credential_pair(key, value) {
    is_contextual_credential(key, value)
}

# Recursively traverse hash and collect all key-value pairs with string values
collect_string_pairs(node, current_path) = pairs {
    node.ir_type == "Hash"
    pairs := { [new_path, value] |
        pair := node.value[_]
        key_node := pair.key
        key_node.ir_type == "String"
        new_key := key_node.value
        value_node := pair.value
        value_node.ir_type == "String"
        new_path := concat(".", [current_path, new_key])
    }
}

collect_string_pairs(node, current_path) = pairs {
    node.ir_type == "Hash"
    pairs := { [p, v] |
        pair := node.value[_]
        key_node := pair.key
        key_node.ir_type == "String"
        new_key := key_node.value
        value_node := pair.value
        value_node.ir_type == "Hash"
        new_path := concat(".", [current_path, new_key])
        nested_pairs := collect_string_pairs(value_node, new_path)
        [p, v] := nested_pairs[_]
    }
}

get_credential_pairs(node) = pairs {
    string_pairs := collect_string_pairs(node, "")
    pair := string_pairs[_]
    key := pair[0]
    value := pair[1]
    is_credential_pair(key, value)
    pairs := [[key, value]]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    
    pairs := get_credential_pairs(attr.value)
    pair := pairs[_]
    key := pair[0]
    value := pair[1]
    
    result := {
        "type": "sec_hard_secr",
        "element": value,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested hash attribute. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    
    pairs := get_credential_pairs(var.value)
    pair := pairs[_]
    key := pair[0]
    value := pair[1]
    
    result := {
        "type": "sec_hard_secr",
        "element": value,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested hash variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_credential_context(attr.name, attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in a sensitive attribute. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    is_credential_context(var.name, var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials in a sensitive variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_contextual_credential(attr.name, attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in a contextual attribute. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    is_contextual_credential(var.name, var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials in a contextual variable. (CWE-798)"
    }
}