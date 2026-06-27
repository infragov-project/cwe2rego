package glitch

import data.glitch_lib

# Unencrypted protocol patterns
unencrypted_url_patterns := {"http://", "ftp://", "telnet://"}
bare_unencrypted_protocols := {"http", "ftp", "telnet"}

# Field names that indicate URL/endpoint configurations
url_endpoint_fields := {"url", "endpoint", "address", "hostname", "source", "location", "connection", "uri", "connection_string", "broker_url", "server_address", "root_url", "base_url", "api_url", "external_url", "callback_url", "redirect_url", "login_url", "logout_url", "auth_url", "token_url", "issuer_url", "jwks_url", "userinfo_url"}

# Field names that indicate protocol/scheme selection
protocol_scheme_fields := {"protocol", "scheme", "frontend_protocol", "listener_protocol", "container_protocol", "service_protocol"}

# Field names indicating TLS/SSL verification settings
verification_fields := {"validate_certs", "ssl_verify", "tls_verify", "verify_ssl", "verify_peer", "verifypeer", "insecure_skip_verify", "ssl_skip_verify", "tls_skip_verify", "ignore_certificate_errors", "ignore_certificate", "accept_insecure_connections", "strictssl", "strict_ssl", "check_ssl", "check_certificate", "certificate_validation", "ssl_validation", "tls_validation"}

# Field names indicating SSL/TLS usage
ssl_tls_usage_fields := {"ssl", "tls", "use_ssl", "use_tls", "enable_ssl", "enable_tls", "start_tls", "starttls", "ssl_mode", "tls_mode", "require_ssl", "ssl_required", "tls_required", "secure", "https", "enforce_https"}

# Disabled/insecure value patterns
disabled_values := {"false", "no", "off", "disabled", "0", "none"}

# Enabled value patterns for insecure settings
enabled_values := {"true", "yes", "on", "enabled", "1"}

# Weak TLS/SSL versions
weak_tls_versions := {"tls1.0", "tls1_0", "tlsv1.0", "tlsv1_0", "sslv2", "sslv3", "ssl2", "ssl3", "tls1", "tlsv1", "1.0", "1_0"}

# Check if string starts with unencrypted URL pattern
string_has_unencrypted_protocol(s) {
    lower_s := lower(s)
    pattern := unencrypted_url_patterns[_]
    startswith(lower_s, pattern)
}

# Check if bare protocol value is unencrypted
is_bare_unencrypted_protocol(s) {
    lower(s) == bare_unencrypted_protocols[_]
}

# Check if value is disabled/false
is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    lower(value.value) == disabled_values[_]
} else {
    value.ir_type == "Integer"
    value.value == 0
}

# Check for weak TLS version
is_weak_tls_version(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    lower_val == weak_tls_versions[_]
}

# Check if field name matches URL/endpoint patterns
is_url_endpoint_field(name) {
    lower_name := lower(name)
    pattern := url_endpoint_fields[_]
    contains(lower_name, pattern)
}

# Check if field name matches protocol/scheme patterns
is_protocol_scheme_field(name) {
    lower_name := lower(name)
    pattern := protocol_scheme_fields[_]
    lower_name == pattern
}

# Check if field name indicates verification setting
is_verification_field(name) {
    lower_name := lower(name)
    pattern := verification_fields[_]
    lower_name == pattern
}

# Check if field name indicates SSL/TLS usage
is_ssl_tls_usage_field(name) {
    lower_name := lower(name)
    pattern := ssl_tls_usage_fields[_]
    lower_name == pattern
}

# Walk through any value type to find unencrypted protocols in String nodes
find_unencrypted_in_value(value) {
    walk(value, [path, node])
    node.ir_type == "String"
    string_has_unencrypted_protocol(node.value)
} else {
    walk(value, [path, node])
    node.ir_type == "String"
    is_bare_unencrypted_protocol(node.value)
}

# Check Hash/Array entries recursively for insecure configurations
check_entry_insecure(entry) {
    is_protocol_scheme_field(entry.key.value)
    find_unencrypted_in_value(entry.value)
} else {
    is_url_endpoint_field(entry.key.value)
    find_unencrypted_in_value(entry.value)
} else {
    is_verification_field(entry.key.value)
    is_disabled(entry.value)
} else {
    is_ssl_tls_usage_field(entry.key.value)
    is_disabled(entry.value)
} else {
    is_tls_version_field(entry.key.value)
    is_weak_tls_version(entry.value)
}

# Check if field is tls_version
is_tls_version_field(name) {
    lower(name) == "tls_version"
} else {
    lower(name) == "ssl_version"
} else {
    lower(name) == "min_tls_version"
}

# Walk through complex structure (Hash/Array) and check entries
walk_and_check_insecure(node) {
    walk(node, [path, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    check_entry_insecure(entry)
}

# Check Variable value - handles String, Hash, Array, Sum, FunctionCall
is_insecure_variable(var) {
    var.value.ir_type == "String"
    string_has_unencrypted_protocol(var.value.value)
} else {
    var.value.ir_type == "String"
    is_bare_unencrypted_protocol(var.value.value)
} else {
    var.value.ir_type == "Hash"
    entry := var.value.value[_]
    check_entry_insecure(entry)
} else {
    var.value.ir_type == "Array"
    walk_and_check_insecure(var.value)
} else {
    find_unencrypted_in_value(var.value)
}

# Check Attribute value - handles String, Hash, Array, Sum, FunctionCall
is_insecure_attr(attr) {
    attr.value.ir_type == "String"
    string_has_unencrypted_protocol(attr.value.value)
} else {
    attr.value.ir_type == "String"
    is_bare_unencrypted_protocol(attr.value.value)
} else {
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    check_entry_insecure(entry)
} else {
    attr.value.ir_type == "Array"
    walk_and_check_insecure(attr.value)
} else {
    find_unencrypted_in_value(attr.value)
}

# Detect unencrypted protocols in URL/endpoint fields (attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_url_endpoint_field(attr.name)
    is_insecure_attr(attr)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol detected in URL or endpoint field. (CWE-319)"
    }
}

# Detect unencrypted protocols in protocol/scheme fields (attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_protocol_scheme_field(attr.name)
    is_insecure_attr(attr)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol scheme detected. (CWE-319)"
    }
}

# Detect disabled certificate validation (attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_verification_field(attr.name)
    is_disabled(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation or TLS verification disabled. (CWE-319)"
    }
}

# Detect disabled SSL/TLS (attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_ssl_tls_usage_field(attr.name)
    is_disabled(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL/TLS encryption disabled. (CWE-319)"
    }
}

# Detect weak TLS version (attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_tls_version_field(attr.name)
    is_weak_tls_version(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak TLS version configured. (CWE-319)"
    }
}

# Helper to check if ir_type is Hash or Array
is_complex_type(t) {
    t == "Hash"
} else {
    t == "Array"
}

# Detect insecure configurations in nested Hash/Array attributes via generic walk
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_complex_type(attr.value.ir_type)
    walk(attr.value, [path, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    check_entry_insecure(entry)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol or TLS configuration in nested structure. (CWE-319)"
    }
}

# Detect unencrypted protocols in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_url_endpoint_field(var.name)
    is_insecure_variable(var)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol detected in variable URL or endpoint. (CWE-319)"
    }
}

# Detect unencrypted protocols in protocol/scheme variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_protocol_scheme_field(var.name)
    is_insecure_variable(var)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol scheme in variable. (CWE-319)"
    }
}

# Detect disabled certificate validation in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_verification_field(var.name)
    is_disabled(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled in variable. (CWE-319)"
    }
}

# Detect disabled SSL/TLS in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_ssl_tls_usage_field(var.name)
    is_disabled(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL/TLS disabled in variable. (CWE-319)"
    }
}

# Detect weak TLS version in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_tls_version_field(var.name)
    is_weak_tls_version(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak TLS version in variable. (CWE-319)"
    }
}

# Detect insecure configurations inside Hash variable values via walk
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    walk(var.value, [path, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    check_entry_insecure(entry)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol or TLS configuration in variable hash. (CWE-319)"
    }
}

# Detect insecure configurations inside Array variable values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    walk(var.value, [path, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    check_entry_insecure(entry)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol or TLS configuration in variable array. (CWE-319)"
    }
}