package glitch

import data.glitch_lib

empty_password_keywords := {"password", "passwd", "pwd", "secret", "credentials", "auth_token", "api_key", "admin_password", "db_password", "root_password", "service_account_key", "tls_private_key", "certificate_password", "keystore_password", "encryption_key", "decryption_key", "master_key", "access_key_secret", "client_secret", "smtp_password", "ldap_password", "ad_password", "vpn_preshared_key", "ipsec_secret", "rds_password", "database_master_password", "connection_string"}

auth_context_keywords := {"authentication", "login", "signin", "auth", "username", "user"}

is_empty_value(node) {
    node.ir_type == "String"
    count(trim(node.value, " \t\n\r")) == 0
}

is_empty_value(node) {
    node.ir_type == "Null"
}

is_empty_value(node) {
    node.ir_type == "Undef"
}

is_password_related_key(key) {
    lower_key := lower(key)
    k := empty_password_keywords[_]
    contains(lower_key, k)
}

is_in_auth_context(parent_block) {
    attrs := glitch_lib.all_attributes(parent_block)
    attr := attrs[_]
    lower_name := lower(attr.name)
    k := auth_context_keywords[_]
    contains(lower_name, k)
}

has_empty_value(node) {
    is_empty_value(node)
}

has_empty_value(node) {
    walk(node, [_, n])
    is_empty_value(n)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]

    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]

    is_password_related_key(attr.name)

    has_empty_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    is_password_related_key(var.name)

    has_empty_value(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]

    is_in_auth_context(au)

    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]

    lower_name := lower(attr.name)
    contains(lower_name, "pass")

    has_empty_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Credentials should not be empty or null. (CWE-258)"
    }
}