package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "token", "key", "api_key", "access_key", "auth_token", "private_key", "certificate", "credential", "client_secret", "oauth_client_secret", "ssh_key", "master_password", "superuser_password", "bootstrap_password", "initial_password", "setup_password"}

credential_suffixes := {"_password", "_secret", "_key", "_token", "_pwd"}

default_passwords := {"password", "123456", "default", "changeme", "admin", "root", "guest", "user", "login", "welcome", "master", "test", "temp", "temporary", "example", "demo"}

is_credential_name(name) {
    lower_name := lower(name)
    kw := credential_keywords[_]
    lower_name == kw
}

is_credential_name(name) {
    lower_name := lower(name)
    suffix := credential_suffixes[_]
    endswith(lower_name, suffix)
}

is_default_password(val) {
    lower_val := lower(val)
    dp := default_passwords[_]
    lower_val == dp
}

is_base64(val) {
    regex.match("^[A-Za-z0-9+/]{20,}[A-Za-z0-9+/=]{0,4}$", val)
}

is_hash_like(val) {
    regex.match("^\\$[0-9a-zA-Z]+\\$", val)
}

looks_like_secret_val(val) {
    is_default_password(val)
}

looks_like_secret_val(val) {
    is_base64(val)
}

looks_like_secret_val(val) {
    is_hash_like(val)
}

looks_like_secret_val(val) {
    count(val) >= 8
    val != "true"
    val != "false"
    val != ""
    regex.match("[A-Za-z]", val)
    regex.match("[0-9]", val)
}

is_hardcoded_credential(key_name, val) {
    is_credential_name(key_name)
    looks_like_secret_val(val)
}

hash_has_creds(h) = results {
    results := {result |
        [_, n] := walk(h)
        n.ir_type == "KeyValue"
        k := n.key
        k.ir_type == "String"
        key_name := k.value
        v := n.value
        v.ir_type == "String"
        val := v.value
        is_hardcoded_credential(key_name, val)
        result := {
            "type": "sec_hard_secr",
            "element": n,
            "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
        }
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {v | v := parent.variables[_]}
    var := vars[_]
    var.value.ir_type == "String"
    is_credential_name(var.name)
    looks_like_secret_val(var.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {v | v := parent.variables[_]}
    var := vars[_]
    var.value.ir_type == "Hash"
    cred_results := hash_has_creds(var.value)
    cr := cred_results[_]
    result := {
        "type": cr.type,
        "element": cr.element,
        "path": parent.path,
        "description": cr.description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_credential_name(attr.name)
    attr.value.ir_type == "String"
    looks_like_secret_val(attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    cred_results := hash_has_creds(attr.value)
    cr := cred_results[_]
    result := {
        "type": cr.type,
        "element": cr.element,
        "path": parent.path,
        "description": cr.description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    [_, item] := walk(attr.value)
    item.ir_type == "Hash"
    cred_results := hash_has_creds(item)
    cr := cred_results[_]
    result := {
        "type": cr.type,
        "element": cr.element,
        "path": parent.path,
        "description": cr.description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_name(attr.name)
    attr.value.ir_type == "String"
    looks_like_secret_val(attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    blocks := {b | b := parent.unit_blocks[_]}
    block := blocks[_]
    block.path == ""
    vars := {v | v := block.variables[_]}
    var := vars[_]
    is_credential_name(var.name)
    var.value.ir_type == "String"
    looks_like_secret_val(var.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    blocks := {b | b := parent.unit_blocks[_]}
    block := blocks[_]
    atomic_units := glitch_lib.all_atomic_units(block)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_credential_name(attr.name)
    attr.value.ir_type == "String"
    looks_like_secret_val(attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}