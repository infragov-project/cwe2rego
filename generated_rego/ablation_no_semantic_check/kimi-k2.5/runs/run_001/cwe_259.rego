package glitch

import data.glitch_lib

sensitive_keywords := {
    "password", "passwd", "pwd", "secret", "token", "key", "credential", "auth",
    "master_password", "admin_password", "root_password", "client_secret",
    "service_principal_secret", "private_key", "certificate", "ssh_key",
    "api_key", "access_key", "secret_key", "registry_password",
    "image_pull_secret", "vpn_shared_key", "ipsec_secret", "radius_secret"
}

default_passwords := {
    "default", "admin", "root", "changeme", "password123", "test", "demo",
    "example", "123456", "qwerty", "password", "letmein", "welcome"
}

is_sensitive_key(key) {
    lower_key := lower(key)
    kw := sensitive_keywords[_]
    contains(lower_key, kw)
}

is_default_password(value) {
    default_pw := default_passwords[_]
    lower(value.value) == default_pw
}

has_hardcoded_string(expr) {
    expr.ir_type == "String"
    expr.value != ""
    not expr.value == "null"
    not startswith(expr.value, "${")
    not startswith(expr.value, "{{")
    not contains(expr.value, "vault")
    not contains(expr.value, "secret")
    not contains(expr.value, "kms")
    not contains(expr.value, "parameter")
}

has_base64_encoding(expr) {
    expr.ir_type == "String"
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", expr.value)
}

hash_contains_secret(hash, key_context) {
    [path, node] := walk(hash.value)
    node.ir_type == "String"
    key_fragment := path[count(path) - 1]
    is_string(key_fragment)
    key_str := sprintf("%v", [key_fragment])
    is_sensitive_key(key_context)
    has_hardcoded_string(node)
}

hash_contains_secret(hash, key_context) {
    [path, node] := walk(hash.value)
    node.ir_type == "String"
    key_fragment := path[count(path) - 1]
    is_string(key_fragment)
    key_str := sprintf("%v", [key_fragment])
    is_sensitive_key(key_str)
    has_hardcoded_string(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_key(attr.name)
    attr.value.ir_type == "String"
    has_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hardcoding sensitive credentials in configuration files. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_sensitive_key(var.name)
    var.value.ir_type == "String"
    has_hardcoded_string(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hardcoding sensitive credentials in configuration files. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    hash_contains_secret(attr.value, attr.name)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hardcoding sensitive credentials in nested configuration structures. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    is_sensitive_key(attr.name)
    has_hardcoded_string(item)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hardcoding sensitive credentials in array structures. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_key(attr.name)
    attr.value.ir_type == "String"
    has_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hardcoding sensitive credentials in resource definitions. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    hash_contains_secret(attr.value, attr.name)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hardcoding sensitive credentials in nested resource configurations. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_key(attr.name)
    attr.value.ir_type == "String"
    is_default_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Default Password - Avoid using default or weak passwords in configuration files. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_sensitive_key(var.name)
    var.value.ir_type == "String"
    is_default_password(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Default Password - Avoid using default or weak passwords in configuration files. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_key(attr.name)
    attr.value.ir_type == "String"
    is_default_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Default Password - Avoid using default or weak passwords in resource definitions. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_key(attr.name)
    attr.value.ir_type == "String"
    has_base64_encoding(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Base64 Encoded Secret - Base64 is not encryption. Use proper secret management instead. (CWE-259)"
    }
}