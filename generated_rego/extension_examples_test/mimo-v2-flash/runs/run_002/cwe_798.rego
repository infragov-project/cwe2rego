package glitch

import data.glitch_lib

credential_keywords := {"password", "secret", "key", "token", "credential", "auth", "api_key", "access_key", "secret_key", "client_secret", "private_key", "shared_secret", "auth_token"}

is_credential_name(name) {
    kw := credential_keywords[_]
    regex.match(sprintf("(?i).*%s", [kw]), name)
}

find_credentials_in_value(value, path, parent_path) = results {
    results := {{"element": value, "path": parent_path, "description": sprintf("Hard-coded credential in nested structure (CWE-798)", [])} |
        walk(value, [p, n])
        n.ir_type == "String"
        p[_] == "key"
        key_node := value.value[p[1]].key
        is_credential_name(key_node.value)
        n.value != ""
        not glitch_lib.traverse_var(n)
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables in parent
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_credential_name(var.name)
    var.value.ir_type == "String"
    var.value.value != ""
    not glitch_lib.traverse_var(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in variable '%s' (CWE-798)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Attributes in parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_name(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    not glitch_lib.traverse_var(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in attribute '%s' (CWE-798)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Atomic Units for credential-like attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_credential_name(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    not glitch_lib.traverse_var(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in atomic unit attribute '%s' (CWE-798)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check nested Hash structures for credentials
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    var.value.ir_type == "Hash"
    walk(var.value, [path, node])
    node.ir_type == "String"
    path[_] == "key"
    key_node := var.value.value[path[1]].key
    is_credential_name(key_node.value)
    node.value != ""
    not glitch_lib.traverse_var(node)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in nested hash (CWE-798)")
    }
}