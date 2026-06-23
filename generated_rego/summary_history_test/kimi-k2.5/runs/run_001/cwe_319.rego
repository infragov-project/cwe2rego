package glitch

import data.glitch_lib
import future.keywords.in

insecure_protocols := {"http", "ftp", "smtp", "ldap", "telnet", "pop3", "imap"}

insecure_bool_strings := {"no", "false", "off", "0", "disable", "disabled"}

insecure_ssl_modes := {"DISABLED", "ALLOW", "PREFERRED"}

insecure_tls_versions := {"TLS1_0", "TLS1_1", "SSL", "SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "1.0", "1.1"}

cert_validation_attrs := {
    "validate_certs", "verify_ssl", "verify", "ssl_verify", "verify_certs",
    "verify_server_certificate", "verify_ca", "verify_certificate", "ssl_verify_peer",
    "insecure_skip_verify", "skip_verify", "disable_certificate_validation"
}

security_protocol_attrs := {
    "protocol", "scheme", "listener_protocol", "frontend_protocol", 
    "backend_protocol", "target_protocol", "upstream_protocol",
    "transfer_protocol", "access_protocol", "mount_protocol",
    "security_protocol", "auth_protocol"
}

ssl_config_attrs := {
    "ssl_mode", "ssl_policy", "tls_policy", "encryption_policy",
    "min_tls_version", "tls_version", "ssl_version", "minimum_protocol",
    "cipher_suites", "sasl_mechanism"
}

expr_has_insecure_url(root) {
    [_, node] := walk(root)
    node.ir_type == "String"
    str := lower(node.value)
    startswith(str, "http://")
}

expr_has_insecure_url(root) {
    [_, node] := walk(root)
    node.ir_type == "String"
    str := lower(node.value)
    startswith(str, "ftp://")
}

is_insecure_protocol(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    insecure_protocols[lower_val]
}

is_insecure_bool_string(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    insecure_bool_strings[lower_val]
}

is_disabled_cert_validation(attr_name, value) {
    cert_validation_attrs[attr_name]
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled_cert_validation(attr_name, value) {
    cert_validation_attrs[attr_name]
    value.ir_type == "String"
    is_insecure_bool_string(value)
}

is_insecure_tls_version(value) {
    value.ir_type == "String"
    upper_val := upper(value.value)
    insecure_tls_versions[upper_val]
}

is_insecure_tls_version(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    startswith(lower_val, "tls1.0")
}

is_insecure_tls_version(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    startswith(lower_val, "tls1.1")
}

is_insecure_tls_version(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    startswith(lower_val, "ssl")
}

is_insecure_ssl_mode(value) {
    value.ir_type == "String"
    upper_val := upper(value.value)
    insecure_ssl_modes[upper_val]
}

get_line(elem) = val {
    val := elem.line
} else = 0 { true }

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_disabled_cert_validation(attr.name, attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]

    is_disabled_cert_validation(node.name, node.value)

    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    security_protocol_attrs[attr.name]
    is_insecure_protocol(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    
    some entry in var.value.value
    entry.key.ir_type == "String"
    security_protocol_attrs[entry.key.value]
    is_insecure_protocol(entry.value)
    entry_line := get_line(entry.value)
    entry_line > 0

    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    ssl_config_attrs[attr.name]
    is_insecure_tls_version(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure TLS/SSL version. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "ssl_mode"
    is_insecure_ssl_mode(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL mode allows cleartext. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    expr_has_insecure_url(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL scheme in connection. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    expr_has_insecure_url(var.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in variable. (CWE-319)"
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
    some entry in attr.value.value
    expr_has_insecure_url(entry.value)
    entry_line := get_line(entry.value)
    entry_line > 0

    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in configuration object. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "Array"
    some elem in attr.value.value
    expr_has_insecure_url(elem)
    elem_line := get_line(elem)
    elem_line > 0

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in array configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "port"
    attr.value.ir_type == "Integer"
    attr.value.value == 80

    not has_tls_indicator(attrs)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP port (80) without TLS indicators. (CWE-319)"
    }
}

has_tls_indicator(attrs) {
    other := attrs[_]
    other.name == "protocol"
    other.value.ir_type == "String"
    lower(other.value.value) == "https"
}

has_tls_indicator(attrs) {
    other := attrs[_]
    other.name == "scheme"
    other.value.ir_type == "String"
    lower(other.value.value) == "https"
}

has_tls_indicator(attrs) {
    other := attrs[_]
    tls_names := {"tls_enabled", "ssl_enabled", "enable_https", "https_only", "use_ssl", "ssl"}
    tls_names[other.name]
    other.value.ir_type == "Boolean"
    other.value.value == true
}

has_tls_indicator(attrs) {
    other := attrs[_]
    other.name == "ssl_mode"
    other.value.ir_type == "String"
    upper(other.value.value) == "REQUIRED"
}

has_tls_indicator(attrs) {
    other := attrs[_]
    other.name == "port"
    other.value.ir_type == "Integer"
    other.value.value == 443
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    [_, found] := walk(var.value)
    expr_has_insecure_url(found)
    found.line > 0

    result := {
        "type": "sec_https",
        "element": found,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in nested configuration. (CWE-319)"
    }
}