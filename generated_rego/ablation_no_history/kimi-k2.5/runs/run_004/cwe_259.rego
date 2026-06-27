package glitch

import data.glitch_lib

is_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "password")
    not contains(lower_name, "passphrase")
    not contains(lower_name, "passwordless")
    not contains(lower_name, "no_password")
}

is_password_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_secret")
}

is_password_field(name) {
    lower_name := lower(name)
    startswith(lower_name, "secret_")
}

is_password_field(name) {
    lower_name := lower(name)
    startswith(lower_name, "pwd")
}

is_password_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_pwd")
}

is_password_field(name) {
    lower_name := lower(name)
    lower_name == "key"
}

is_password_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_key")
    not contains(lower_name, "ssh_key")
    not contains(lower_name, "public_key")
}

is_password_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_credential")
}

is_password_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_auth")
}

is_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "_auth_")
}

is_password_field(name) {
    lower_name := lower(name)
    startswith(lower_name, "auth_")
}

is_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "token")
    not contains(lower_name, "tokenize")
}

is_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "_passwd")
}

is_password_field(name) {
    lower_name := lower(name)
    startswith(lower_name, "passwd")
}

is_secret_reference(value) {
    contains(value, "${")
}

is_secret_reference(value) {
    contains(value, "{{")
}

is_secret_reference(value) {
    contains(value, "vault:")
}

is_secret_reference(value) {
    contains(value, "data.")
}

is_secret_reference(value) {
    contains(value, "module.")
}

is_secret_reference(value) {
    contains(value, "var.")
}

is_secret_reference(value) {
    contains(value, "lookup(")
}

is_secret_reference(value) {
    contains(value, "local_sensitive")
}

is_secret_reference(value) {
    contains(value, "sensitive(")
}

is_secret_reference(value) {
    contains(value, "environment(")
}

is_secret_reference(value) {
    contains(value, "ENV[")
}

is_secret_reference(value) {
    regex.match("^[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_]", value)
}

is_literal_password(value) {
    count(value) > 0
    not is_secret_reference(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])

    node.ir_type == "Variable"

    is_password_field(node.name)

    walk(node.value, [_, val_node])

    val_node.ir_type == "String"
    count(val_node.value) > 0
    is_literal_password(val_node.value)

    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])

    node.ir_type == "Attribute"

    is_password_field(node.name)

    walk(node.value, [_, val_node])

    val_node.ir_type == "String"
    count(val_node.value) > 0
    is_literal_password(val_node.value)

    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, hash_node])

    hash_node.ir_type == "Hash"

    walk(hash_node.value, [_, kv_pair])

    kv_pair.ir_type == "Assign"

    is_password_field(kv_pair.left.value)

    walk(kv_pair.right, [_, val_node])

    val_node.ir_type == "String"
    count(val_node.value) > 0
    is_literal_password(val_node.value)

    result := {
        "type": "sec_hard_pass",
        "element": hash_node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}