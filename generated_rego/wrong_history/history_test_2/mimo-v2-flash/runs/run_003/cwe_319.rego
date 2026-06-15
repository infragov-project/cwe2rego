package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    insecure_protocols := {"http", "ftp", "smtp", "telnet", "ldap"}
    insecure_attributes := {"protocol", "http", "ftp", "smtp", "telnet", "ldap", "https", "ssl", "tls"}

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in insecure_attributes
    attr.value.ir_type == "String"
    protocol_value := attr.value.value
    protocol_value in insecure_protocols

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol used for data transmission (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    encryption_flags := {"https", "ssl", "tls", "encryption_enabled", "secure_transfer", "use_ssl", "enable_tls", "force_https", "secure_cookies", "encrypted_connections", "secure_transfer_required"}

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in encryption_flags
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption flag disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    secret_attributes := {"password", "secret", "key", "token", "api_key", "credential"}

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in secret_attributes
    attr.value.ir_type == "String"

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Plaintext secret in configuration (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    logging_attributes := {"logging", "debug", "verbose"}

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in logging_attributes
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Logging enabled with potential sensitive data (CWE-319)"
    }
}