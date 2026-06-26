package glitch

import data.glitch_lib

is_security_flag(name) {
    regex.match("(?i)(validate_certs|https_only|ssl_enabled|tls_enabled|require_https|secure_transfer|force_ssl|enforce_https)", name)
}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

has_insecure_url(node) {
    walk(node, [_, leaf])
    leaf.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", leaf.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_security_flag(attr.name)
    is_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption enforcement is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    has_insecure_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use of insecure protocol in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    has_insecure_url(variable.value)
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use of insecure protocol in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    walk(variable.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.ir_type == "String"
    regex.match("(?i)^protocol$", pair.key.value)
    pair.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|smtp|ldap|pop3|imap)$", pair.value.value)
    result := {
        "type": "sec_https",
        "element": pair.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use of insecure cleartext protocol. (CWE-319)"
    }
}