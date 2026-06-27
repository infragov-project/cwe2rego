package glitch

import data.glitch_lib

# Check if value represents disabled/false state for integrity checks
is_disabled_value(value) {
    value.ir_type == "Boolean"
    not value.value
} else {
    value.ir_type == "String"
    regex.match("^(?i:false|no|off|disable|disabled|none|0|skip|ignore)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

# Check if URL uses insecure HTTP protocol
is_insecure_url(value) {
    value.ir_type == "String"
    l_val := lower(value.value)
    startswith(l_val, "http://")
}

# Helper to recursively collect all values with their paths from nested structures
collect_all_values(node, base_path) = values {
    values := {{"path": path, "value": v, "key_name": key_name} |
        walk(node, [walk_path, n])
        n.ir_type == "Hash"
        kv := n.value[_]
        kv.key.ir_type == "String"
        key_name := kv.key.value
        v := kv.value
        path := concat(".", array.concat(base_path, [key_name]))
    }
}

# Find all nested values in a Hash structure
find_nested_hash_values(root) = result {
    result := {[path, value_key, value_node] |
        walk(root, [_, node])
        node.ir_type == "Hash"
        entry := node.value[_]
        entry.key.ir_type == "String"
        path := entry.key.value
        value_node := entry.value
        value_key := entry.key.value
    }
}

# Check if attribute name indicates SSL/TLS/certificate validation
is_cert_validation_attr(name) {
    regex.match("(?i)^(verify_?(ssl|tls|cert|peer)|validate_?certs?|insecure|skip_?verify|ssl_?verify|tls_?verify|cert_?validation|insecure_?skip_?verify)$", name)
}

# Check if attribute name indicates GPG/signature verification
is_gpg_validation_attr(name) {
    regex.match("(?i)^(gpgcheck|repo_?gpgcheck|pkg_?gpgcheck|enable_?gpg|sign(ature)?_?check|verify_?sign(ature)?|signed_?by)$", name)
}

# Check if attribute name indicates encryption
is_encryption_attr(name) {
    regex.match("(?i)^(encrypt(ed)?|ssl|tls|use_?ssl|require_?ssl|ssl_?mode|transport)$", name)
}

# Check if attribute name indicates source/URL
is_source_attr(name) {
    regex.match("(?i)^(source|url|uri|src|location|download|baseurl|mirrorlist)$", name)
}

# Check if attribute name indicates integrity verification
is_integrity_attr(name) {
    regex.match("(?i)^(checksum|hash|md5|sha(1|256|384|512)?|digest|signature|gpg_?key|verify|integrity|etag|content_?md5)$", name)
}

# Check if we're in a vars block (skip cert validation checks there)
is_vars_block(parent) {
    parent.type == "vars"
}

# Check if AtomicUnit type is file/resource download type
is_download_unit_type(utype) {
    regex.match("(?i)^(remote_file|file|get_url|uri|download|fetch|archive|http_request|wget|curl)$", utype)
}

# Detect disabled certificate/SSL/TLS validation in AtomicUnit attributes (not in vars)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    not is_vars_block(parent)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_cert_validation_attr(attr.name)
    is_disabled_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Certificate/SSL/TLS validation is disabled. (CWE-353)"
    }
}

# Detect disabled GPG/signature verification in AtomicUnit attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_gpg_validation_attr(attr.name)
    is_disabled_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - GPG/signature verification is disabled. (CWE-353)"
    }
}

# Detect disabled GPG check in nested Hash structures within Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    [_, key_name, value_node] := find_nested_hash_values(var.value)
    is_gpg_validation_attr(key_name)
    is_disabled_value(value_node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing support for integrity check - GPG signature check disabled in configuration. (CWE-353)"
    }
}

# Detect insecure HTTP source without integrity verification in download resources
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Match file download/fetch resource types
    is_download_unit_type(node.type)
    
    attrs := glitch_lib.all_attributes(node)
    
    # Find source URL attribute with insecure HTTP
    attr := attrs[_]
    is_source_attr(attr.name)
    is_insecure_url(attr.value)
    
    # Check no integrity attribute exists in the node
    not has_integrity_verification(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure HTTP source without integrity verification. (CWE-353)"
    }
}

# Detect generic insecure HTTP sources in any resource without integrity verification
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Don't limit to just download types - check any resource with source/URL
    attrs := glitch_lib.all_attributes(node)
    
    attr := attrs[_]
    is_source_attr(attr.name)
    is_insecure_url(attr.value)
    
    # Check no integrity attribute exists
    not has_integrity_verification(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure HTTP source without integrity verification. (CWE-353)"
    }
}

# Helper to check if integrity verification attribute exists
has_integrity_verification(attrs) {
    attr := attrs[_]
    is_integrity_attr(attr.name)
}