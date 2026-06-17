package glitch

import data.glitch_lib

secure_flag_names := {
    "ssl_enabled", "tls_enabled", "https_only", "enforce_https",
    "enable_https", "require_ssl", "enforce_ssl",
    "secure_transfer", "secure_transfer_required",
    "encryption_in_transit", "transit_encryption_enabled",
    "require_secure_transport", "enablehttpstrafficonly",
    "validate_certs"
}

insecure_flag_names := {
    "insecure", "disable_ssl", "insecure_skip_verify",
    "skip_ssl_verification"
}

tls_version_attr_names := {
    "minimum_tls_version", "tls_version", "ssl_policy",
    "ssl_protocols", "tls_policy"
}

disabled_string_values := {
    "disabled", "none", "off", "false", "disable", "0", "no"
}

is_disabled(val) {
    val.ir_type == "Boolean"
    val.value == false
}

is_disabled(val) {
    val.ir_type == "String"
    lower(val.value) == disabled_string_values[_]
}

value_has_cleartext_url(val) {
    walk(val, [_, node])
    node.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp)://", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == secure_flag_names[_]
    is_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption flag is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecure_flag_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure transmission flag is enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    value_has_cleartext_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol URL configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    value_has_cleartext_url(variable.value)
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol URL in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match("(?i)^(protocol|scheme|transport)$", entry.key.value)
    entry.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp|plaintext)$", entry.value.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Protocol set to cleartext. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == tls_version_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(TLSv?1\\.0|TLSv?1\\.1|TLS1_0|TLS1_1|TLS_1_0|TLS_1_1|SSLv?2|SSLv?3)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS/SSL version configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "plaintext"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - PLAINTEXT protocol configured. (CWE-319)"
    }
}