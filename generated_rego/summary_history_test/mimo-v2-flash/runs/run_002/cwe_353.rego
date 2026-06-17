package glitch

import data.glitch_lib
import future.keywords.in

has_insecure_protocol_value(attr) {
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)$", attr.value.value)
}

has_insecure_protocol_value(attr) {
    attr.value.ir_type == "Sum"
    has_insecure_protocol(attr.value)
}

has_insecure_protocol_value(attr) {
    attr.value.ir_type == "VariableReference"
    has_insecure_protocol(attr)
}

has_insecure_protocol_value(attr) {
    attr.value.ir_type == "VariableReference"
    has_insecure_protocol(attr.value)
}

has_insecure_protocol_value(attr) {
    attr.value.ir_type == "VariableReference"
}

has_insecure_protocol(node) {
    code_lower := lower(node.code)
    regex.match("(?i)\\b(https?|ftp|telnet)://", code_lower)
}

has_insecure_protocol(node) {
    code_lower := lower(node.code)
    regex.match("(?i)\\b(https?|ftp|telnet)%3A%2F%2F", code_lower)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some variable in parent.variables
    variable.ir_type == "Variable"
    
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    some hash_entry in node.value
    hash_entry.key.ir_type == "String"
    hash_entry.key.value == "gpgcheck"
    hash_entry.value.ir_type in {"Integer", "String"}
    hash_entry.value.value in {0, "0"}
    
    result := {
        "type": "sec_no_int_check",
        "element": hash_entry,
        "path": parent.path,
        "description": "Disabled integrity checks in repository configuration - GPG signature checking disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    protocol_attributes := {"protocol", "url", "connection_string", "scheme", "source"}
    integrity_attributes := {"checksum_algorithm", "integrity_check", "verify_data", "hashing", "ssl_mode", "tls_version"}
    
    protocol_attributes[attr.name]
    
    has_insecure_protocol_value(attr)
    
    count({a | a := attrs[_]; integrity_attributes[a.name]}) == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity checks for transmission protocol - Protocol configured without corresponding integrity verification attributes. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.code != ""
    
    has_insecure_protocol(node)
    
    integrity_patterns := {
        "checksum_algorithm",
        "integrity_check",
        "verify_data",
        "hashing",
        "ssl_mode",
        "tls_version"
    }
    
    not any_integrity_pattern(node.code, integrity_patterns)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity checks for transmission protocol - Protocol configured without corresponding integrity verification attributes. (CWE-353)"
    }
}

any_integrity_pattern(code, patterns) {
    some pattern in patterns
    contains(code, pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    disabled_security_settings := {
        ["ssl_mode", "disabled"],
        ["encryption_enabled", "false"],
        ["require_tls", "false"],
        ["secure_channel", "false"],
        ["enable_checksum", "false"],
        ["integrity_verification", "disabled"]
    }
    
    setting := disabled_security_settings[_]
    attr.name == setting[0]
    attr.value.ir_type in {"String", "Boolean", "Integer"}
    attr.value.value == setting[1]
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Disabled integrity checks in transmission protocol - Security features like TLS/SSL or checksums are explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.code != ""
    
    disabled_patterns := {
        "validate_certs:\\s*no",
        "ssl_mode:\\s*disabled",
        "encryption_enabled:\\s*false",
        "require_tls:\\s*false",
        "secure_channel:\\s*false",
        "enable_checksum:\\s*false",
        "integrity_verification:\\s*disabled"
    }
    
    code_lower := lower(node.code)
    some pattern in disabled_patterns
    regex.match(pattern, code_lower)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Disabled integrity checks in transmission protocol - Security features like TLS/SSL or checksums are explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    port_attributes := {"port", "ports", "listen_port"}
    port_attributes[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(80|21|23)$", attr.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure port configuration for plaintext protocols - Using ports commonly associated with unencrypted protocols. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.code != ""
    
    insecure_ports := {"80", "21", "23"}
    code_lower := lower(node.code)
    some port in insecure_ports
    regex.match(sprintf("(?i).*\\b%s\\b", [port]), code_lower)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure port configuration for plaintext protocols - Using ports commonly associated with unencrypted protocols. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.code != ""
    
    insecure_protocols := {"http://", "ftp://", "telnet://"}
    code_lower := lower(node.code)
    some protocol in insecure_protocols
    contains(code_lower, protocol)
    
    integrity_patterns := {
        "checksum_algorithm",
        "integrity_check",
        "verify_data",
        "hashing",
        "ssl_mode",
        "tls_version"
    }
    
    not any_integrity_pattern(node.code, integrity_patterns)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity checks for transmission protocol - Protocol configured without corresponding integrity verification attributes. (CWE-353)"
    }
}