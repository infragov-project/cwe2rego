package glitch

import data.glitch_lib

sensitive_fields := {
    "password", "passwd", "pwd", "secret", "secretkey", "secret_key",
    "credentials", "creds", "token", "apitoken", "accesstoken", "authtoken",
    "auth", "authentication", "privatekey", "private_key", "certificate",
    "cert", "clientcert", "connectionstring", "connection_string", "connstr",
    "defaultpassword", "initialpassword", "adminpassword", "sha512_password",
    "key"
}

weak_passwords := {"password", "123456", "admin", "default", "secret", "changeme", "root", "pass"}

is_sensitive_field(name) {
    lower_name := lower(name)
    lower_name == sensitive_fields[_]
}

is_sensitive_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_password")
}

is_sensitive_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_secret")
}

is_sensitive_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_token")
}

is_sensitive_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_key")
}

is_sensitive_name_part(name) {
    parts := split(name, ".")
    part := parts[_]
    is_sensitive_field(part)
}

is_secret_reference(value) {
    value.ir_type == "FunctionCall"
}

is_secret_reference(value) {
    value.ir_type == "MethodCall"
}

is_secret_reference(value) {
    value.ir_type == "VariableReference"
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "vault")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "keyvault")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "secretsmanager")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "parameterstore")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "secretref")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "fromsecret")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "managed_identity")
}

is_secret_reference(strval) {
    is_string(strval)
    lower_str := lower(strval)
    contains(lower_str, "service_account")
}

is_secret_reference(strval) {
    is_string(strval)
    contains(strval, "{{")
}

is_secret_reference(strval) {
    is_string(strval)
    contains(strval, "${")
}

is_hardcoded_value(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_secret_reference(value.value)
}

is_weak_password(strval) {
    lower_str := lower(strval)
    lower_str == weak_passwords[_]
}

is_base64_like(strval) {
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", strval)
}

find_sensitive_in_hash(hash_node, parent_path) = results {
    results := {res |
        hash_node.value[k]
        k.ir_type == "String"
        field_name := k.value
        is_sensitive_field(field_name)
        hash_node.value[k] = v
        v.ir_type == "String"
        is_hardcoded_value(v)
        res := {
            "key": field_name,
            "value": v,
            "hash": hash_node
        }
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    field_name := node.name
    is_sensitive_field(field_name)
    node.value.ir_type == "String"
    is_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    field_name := node.name
    is_sensitive_name_part(field_name)
    node.value.ir_type == "String"
    is_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    field_name := node.name
    is_sensitive_field(field_name)
    node.value.ir_type == "String"
    is_base64_like(node.value.value)
    not is_secret_reference(node.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Obfuscated Hard-coded Password - Base64 encoding does not provide security. Secrets should be retrieved from secure external stores. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    field_name := node.name
    is_sensitive_name_part(field_name)
    node.value.ir_type == "String"
    is_base64_like(node.value.value)
    not is_secret_reference(node.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Obfuscated Hard-coded Password - Base64 encoding does not provide security. Secrets should be retrieved from secure external stores. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    field_name := node.name
    is_sensitive_field(field_name)
    node.value.ir_type == "String"
    is_weak_password(node.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Weak Hard-coded Password - Weak or obvious passwords should not be used even in configuration files. Use secure external stores with strong credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    field_name := node.name
    is_sensitive_name_part(field_name)
    node.value.ir_type == "String"
    is_weak_password(node.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Weak Hard-coded Password - Weak or obvious passwords should not be used even in configuration files. Use secure external stores with strong credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    found := find_sensitive_in_hash(node, parent.path)
    count(found) > 0
    item := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "Hash"
    found := find_sensitive_in_hash(item, parent.path)
    count(found) > 0
    fitem := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": fitem.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_field(field_name)
    v.ir_type == "String"
    is_hardcoded_value(v)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_name_part(field_name)
    v.ir_type == "String"
    is_hardcoded_value(v)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_field(field_name)
    v.ir_type == "String"
    is_base64_like(v.value)
    not is_secret_reference(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Obfuscated Hard-coded Password - Base64 encoding does not provide security. Secrets should be retrieved from secure external stores. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_name_part(field_name)
    v.ir_type == "String"
    is_base64_like(v.value)
    not is_secret_reference(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Obfuscated Hard-coded Password - Base64 encoding does not provide security. Secrets should be retrieved from secure external stores. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_field(field_name)
    v.ir_type == "String"
    is_weak_password(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Weak Hard-coded Password - Weak or obvious passwords should not be used even in configuration files. Use secure external stores with strong credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_name_part(field_name)
    v.ir_type == "String"
    is_weak_password(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Weak Hard-coded Password - Weak or obvious passwords should not be used even in configuration files. Use secure external stores with strong credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "Hash"
    item.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_field(field_name)
    v.ir_type == "String"
    is_hardcoded_value(v)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "Hash"
    item.value[k] = v
    k.ir_type == "String"
    field_name := k.value
    is_sensitive_name_part(field_name)
    v.ir_type == "String"
    is_hardcoded_value(v)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    field_name := attr.name
    is_sensitive_field(field_name)
    attr.value.ir_type == "String"
    is_hardcoded_value(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    field_name := attr.name
    is_sensitive_name_part(field_name)
    attr.value.ir_type == "String"
    is_hardcoded_value(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords or secrets should not be hardcoded in configuration files. Use secure external stores like vaults or key management services. (CWE-259)"
    }
}