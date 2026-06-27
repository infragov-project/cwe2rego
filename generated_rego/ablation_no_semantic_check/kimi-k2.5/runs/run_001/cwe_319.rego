package glitch

import data.glitch_lib

# Helper to check if a string value matches cleartext protocol patterns
is_cleartext_protocol(value) {
    value.ir_type == "String"
    regex.match("^(?i)http://|ftp://|telnet://|smtp://|imap://|pop3://", value.value)
}

# Helper to check for disabled/weak TLS/SSL settings
disabled_security_attrs := {"enablehttpstrafficonly", "https_only", "require_https", "secure_transfer", "verify_ssl", "verify_peer", "insecure_skip_verify", "validation", "verify", "ssl_enforcement", "require_secure_transport", "transit_encryption_enabled", "encryption_in_transit", "in_flight_encryption", "tls", "ssl", "start_tls", "ssl_mode"}

has_disabled_security(name) {
    disabled_security_attrs[lower(name)]
}

# Helper to check for security-enabling attribute names that should be true/enabled
enabling_security_attrs := {"force_https", "enforce_tls", "require_ssl", "use_ssl", "enable_encryption", "server_side_encryption", "encrypted", "sse_enabled", "enable_secure_transport"}

has_enabling_security(name) {
    enabling_security_attrs[lower(name)]
}

# Check if value indicates disabled security (false, "false", "disabled", "none", "off")
is_security_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    lower(value.value) == "false"
} else {
    value.ir_type == "String"
    lower(value.value) == "disabled"
} else {
    value.ir_type == "String"
    lower(value.value) == "none"
} else {
    value.ir_type == "String"
    lower(value.value) == "off"
} else {
    value.ir_type == "String"
    lower(value.value) == "plaintext"
} else {
    value.ir_type == "Null"
}

# Check for weak TLS versions
is_weak_tls_version(value) {
    value.ir_type == "String"
    regex.match("^(?i)1\\.0$|^(?i)1\\.1$|^(?i)tlsv?1\\.0$|^(?i)tlsv?1\\.1$", value.value)
}

# Check for weak cipher indicators in strings
is_weak_cipher(value) {
    value.ir_type == "String"
    regex.match("(?i)rc4|des|3des|null|anon|export", value.value)
}

# Check for unencrypted port numbers
cleartext_ports := {80, 21, 23, 110, 143}

is_cleartext_port(value) {
    value.ir_type == "Integer"
    cleartext_ports[value.value]
} else {
    value.ir_type == "String"
    regex.match("^(80|21|23|110|143)$", value.value)
}

# Check for HTTP protocol specification
is_http_protocol(value) {
    value.ir_type == "String"
    regex.match("^(?i)http$", value.value)
}

# Check for cleartext authentication types
is_cleartext_auth(value) {
    value.ir_type == "String"
    regex.match("^(?i)basic$|^(?i)plain$|^(?i)cleartext$", value.value)
}

# Find cleartext URLs using walk to avoid recursion
has_cleartext_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_cleartext_protocol(n)
}

# Disable security flags set to false/insecure values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    has_disabled_security(attr.name)
    is_security_disabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Transport encryption or certificate validation is disabled, allowing data to be transmitted without encryption. (CWE-319)"
    }
}

# Security-enabling attributes set to false/disabled
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    has_enabling_security(attr.name)
    is_security_disabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security enforcement for encrypted transmission is disabled. (CWE-319)"
    }
}

# Weak TLS version usage
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)tls.*version|min.*tls|ssl.*version|ssl.*policy", attr.name)
    is_weak_tls_version(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Use of weak or deprecated TLS/SSL version that does not provide adequate encryption. (CWE-319)"
    }
}

# Unencrypted protocol specification
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "protocol"
    is_http_protocol(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Use of unencrypted HTTP protocol instead of HTTPS. (CWE-319)"
    }
}

# Weak cipher configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)cipher|encryption.*algorithm", attr.name)
    is_weak_cipher(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Use of weak or broken cryptographic cipher that provides inadequate protection. (CWE-319)"
    }
}

# Cleartext port configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "port"
    is_cleartext_port(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Use of port commonly associated with unencrypted protocols. (CWE-319)"
    }
}

# Cleartext authentication type
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)auth.*type|authentication", attr.name)
    is_cleartext_auth(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Authentication method transmits credentials in cleartext. (CWE-319)"
    }
}

# Hardcoded cleartext URLs in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    has_cleartext_url(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hardcoded URL using unencrypted protocol for transmission of potentially sensitive data. (CWE-319)"
    }
}