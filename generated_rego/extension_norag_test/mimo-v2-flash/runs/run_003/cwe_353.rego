package glitch

import data.glitch_lib

# Define security attributes that should be checked for integrity
security_attributes := {"protocol", "encryption", "authentication", "tls_version", "security_policy", "validate_certs", "gpgcheck", "sslverify", "verify_mode", "checksum_algorithm", "hash_validation", "enable_data_validation", "message_integrity", "acknowledgment_mode", "use_tls", "enforce_tls", "default_security", "allow_plain_text", "auto_checksum", "custom_protocol", "protocol_options", "data_integrity", "baseurl", "source", "url", "mirrorlist", "validate", "checksum", "integrity_check"}

# Define insecure values that indicate missing integrity checks
insecure_string_values := {"none", "disabled", "false", "0", "no", "off", "null", "", "plaintext", "http://", "ftp://", "telnet://", "smtp://", "ldap://", "snmp://"}

# Check if a value is insecure
is_insecure_value(value) = true {
    value.ir_type == "String"
    lower(value.value) in insecure_string_values
} else = true {
    value.ir_type == "String"
    some protocol in {"http://", "ftp://", "telnet://", "smtp://", "ldap://", "snmp://"}
    startswith(lower(value.value), protocol)
} else = true {
    value.ir_type == "Integer"
    value.value == 0
} else = true {
    value.ir_type == "Boolean"
    value.value == false
} else = true {
    value.ir_type == "Null"
}

# Main detection rule for attributes in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) in security_attributes
    is_insecure_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Security attribute with insecure value (CWE-353)"
    }
}

# Detection rule for variables that could affect security
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    is_insecure_value(var.value)
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Variable with insecure value (CWE-353)"
    }
}

# Detection rule for nested attributes in complex structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower(node.name) in security_attributes
    is_insecure_value(node.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Nested security attribute with insecure value (CWE-353)"
    }
}

# Detection rule for insecure strings in any context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    lower(node.value) in insecure_string_values
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure string value (CWE-353)"
    }
}

# Detection rule for insecure URLs in any context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    some protocol in {"http://", "ftp://", "telnet://", "smtp://", "ldap://", "snmp://"}
    startswith(lower(node.value), protocol)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure protocol URL (CWE-353)"
    }
}