package glitch

import data.glitch_lib

insecure_protocol_patterns := ["http://", "ftp://", "telnet://", "smtp://", "http:\\/\\/", "ftp:\\/\\/", "telnet:\\/\\/", "smtp:\\/\\/"]

cleartext_ports := {"80", "21", "23", "25", "110", "143", "389", "8021", "8080"}

security_attrs_disable_pattern := ["validate_certs", "enforce_https", "ssl_required", "tls_required", "require_secure_transport", "verify_peer", "cert_validation", "encrypt", "tls", "ssl", "secure", "use_tls", "use_ssl", "sslmode", "insecure_skip_verify", "verify_ssl", "enable_https_traffic_only"]

security_attrs_enable_pattern := ["tls_disable", "ssl_disable", "disable_tls", "disable_ssl", "enforce_http", "allow_insecure"]

is_false_or_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "false"
    true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "no"
    true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "off"
    true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "disabled"
    true
}

is_true_or_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "true"
    true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "yes"
    true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "on"
    true
} else {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == "enabled"
    true
}

string_has_insecure_protocol(str) {
    lower_str := lower(str)
    pattern := insecure_protocol_patterns[_]
    contains(lower_str, pattern)
}

walk_contains_insecure_protocol(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    string_has_insecure_protocol(n.value)
}

has_insecure_protocol(node) {
    walk_contains_insecure_protocol(node)
}

hash_entry_has_protocol_http(hash) {
    walk(hash, [_, entry])
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
}

hash_entry_has_disabled_security(hash) {
    walk(hash, [_, entry])
    entry.key.ir_type == "String"
    attr_name := lower(entry.key.value)
    attr_pattern := security_attrs_disable_pattern[_]
    contains(attr_name, attr_pattern)
    is_false_or_disabled(entry.value)
}

hash_entry_has_enabled_insecurity(hash) {
    walk(hash, [_, entry])
    entry.key.ir_type == "String"
    attr_name := lower(entry.key.value)
    attr_pattern := security_attrs_enable_pattern[_]
    contains(attr_name, attr_pattern)
    is_true_or_enabled(entry.value)
}

is_security_disable_attr(name) {
    lower_name := lower(name)
    attr_pattern := security_attrs_disable_pattern[_]
    contains(lower_name, attr_pattern)
}

is_security_enable_attr(name) {
    lower_name := lower(name)
    attr_pattern := security_attrs_enable_pattern[_]
    contains(lower_name, attr_pattern)
}

is_cleartext_port_attr(name, value) {
    lower_name := lower(name)
    contains(lower_name, "port")
    value.ir_type == "String"
    cleartext_ports[value.value]
} else {
    lower_name := lower(name)
    contains(lower_name, "port")
    value.ir_type == "Integer"
    port_str := sprintf("%d", [value.value])
    cleartext_ports[port_str]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    string_has_insecure_protocol(var.value.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol detected in URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    has_insecure_protocol(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol detected in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_entry_has_protocol_http(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP protocol in configuration object. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_entry_has_disabled_security(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security disabled in configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_entry_has_enabled_insecurity(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure feature enabled in configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_security_disable_attr(attr.name)
    is_false_or_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security feature is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_security_enable_attr(attr.name)
    is_true_or_enabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure feature is explicitly enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    string_has_insecure_protocol(attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    has_insecure_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_cleartext_port_attr(attr.name, attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext port configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == "protocol"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == "protocol"
    attr.value.ir_type == "Sum"
    walk_contains_insecure_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP protocol configured. (CWE-319)"
    }
}