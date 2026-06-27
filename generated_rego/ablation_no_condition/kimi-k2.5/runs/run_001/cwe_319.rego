package glitch

import data.glitch_lib

# Collect all String values from expression tree using walk
collect_strings(expr) = strings {
    strings := {s |
        walk(expr, [_, node])
        node.ir_type == "String"
        s := lower(node.value)
    }
}

# Check if any string in expression starts with http://
has_http_url(expr) {
    strings := collect_strings(expr)
    s := strings[_]
    startswith(s, "http://")
}

# Check if any string in expression contains https://
has_https_url(expr) {
    strings := collect_strings(expr)
    s := strings[_]
    contains(s, "https://")
}

# Check for protocol: http in hash structures using walk
has_http_protocol(expr) {
    walk(expr, [_, node])
    node.ir_type == "Hash"
    some entry
    entry = node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
}

# Check if value represents false/disabled
is_false_or_disabled(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "no"
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "false"
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "0"
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "off"
}

# Check if value represents true/enabled (for insecure flags)
is_true_or_enabled(val) {
    val.ir_type == "Boolean"
    val.value == true
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "yes"
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "true"
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "1"
} else {
    val.ir_type == "String"
    l := lower(val.value)
    l == "on"
}

# URL-related attribute names
url_attr_names := {"url", "source", "baseurl", "location", "uri", "src", "repo", "endpoint", "address", "host", "hostname"}

# Security-related attribute names for disabling validation
validate_certs_names := {"validate_certs", "verify_ssl", "ssl_verify", "insecure"}
ssl_enable_names := {"ssl_enabled", "ssl", "tls", "use_ssl", "https", "enable_ssl", "tls_verify", "force_ssl"}
insecure_names := {"insecure", "skip_verify", "no_check_certificate", "disable_ssl", "allow_insecure", "ssl_no_verify"}

# Detect HTTP URLs in URL attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == url_attr_names[_]
    has_http_url(attr.value)
    not has_https_url(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use HTTPS instead of HTTP to encrypt data in transit. (CWE-319)"
    }
}

# Detect disabled certificate validation
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == validate_certs_names[_]
    is_false_or_disabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Certificate validation is disabled, allowing potential man-in-the-middle attacks. (CWE-319)"
    }
}

# Detect disabled SSL/TLS
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == ssl_enable_names[_]
    is_false_or_disabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS encryption is disabled, enabling cleartext transmission of sensitive information. (CWE-319)"
    }
}

# Detect enabled insecure mode
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == insecure_names[_]
    is_true_or_enabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure mode is enabled, allowing cleartext transmission of sensitive information. (CWE-319)"
    }
}

# Detect unauthenticated access
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "allow_unauthenticated"
    is_true_or_enabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Enable authentication to prevent unauthorized access to sensitive data. (CWE-319)"
    }
}

# Detect HTTP URLs in variables - use actual value element to report correct line
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    has_http_url(var.value)
    not has_https_url(var.value)

    # Find the actual String element with http:// for correct line reporting
    walk(var.value, [_, node])
    node.ir_type == "String"
    startswith(lower(node.value), "http://")

    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Variable contains HTTP URL without HTTPS, enabling cleartext transmission of sensitive information. (CWE-319)"
    }
}

# Detect protocol: http in variable values - use the actual protocol value element
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    walk(var.value, [_, node])
    node.ir_type == "Hash"
    some entry
    entry = node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"

    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration uses HTTP protocol instead of HTTPS, enabling cleartext transmission. (CWE-319)"
    }
}

# Check attributes in atomic units for protocol: http in nested hashes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    walk(attr.value, [_, hnode])
    hnode.ir_type == "Hash"
    some entry
    entry = hnode.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"

    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration uses HTTP protocol instead of HTTPS, enabling cleartext transmission. (CWE-319)"
    }
}