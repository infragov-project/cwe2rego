package glitch

import data.glitch_lib

# Check for HTTP URL in Sum nodes (string interpolation)
sum_contains_http_url(node) {
    node.ir_type == "Sum"
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("^http://", n.value)
    not regex.match("^https://", n.value)
}

# Find nested key-value pair in Hash by key name, return the entry
find_hash_entry(node, key_name) = entry {
    node.ir_type == "Hash"
    some e
    e = node.value[_]
    e.key.ir_type == "String"
    lower(e.key.value) == lower(key_name)
    entry := e
}

# Check Hash for protocol: http pattern
hash_has_http_protocol(node) {
    entry := find_hash_entry(node, "protocol")
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
}

# Check Hash for HTTP URL in any value
hash_has_http_url(node) {
    node.ir_type == "Hash"
    some e
    e = node.value[_]
    e.value.ir_type == "String"
    regex.match("^http://", e.value.value)
    not regex.match("^https://", e.value.value)
}

# Check Hash for disabled certificate validation
hash_has_disabled_certs(node) {
    entry := find_hash_entry(node, "validate_certs")
    entry.value.ir_type == "String"
    lower(entry.value.value) == "no"
}

# Check Hash for disabled encryption
hash_has_disabled_encryption(node) {
    entry := find_hash_entry(node, "enforce_https")
    entry.value.ir_type == "Boolean"
    entry.value.value == false
}

# Get specific element from attribute or variable for precise reporting
get_element_for_report(attr, var, parent) = elem {
    attr != {}
    elem := attr
} else = elem {
    var != {}
    elem := var
} else = elem {
    elem := parent
}

# Attributes: HTTP URL in string value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    regex.match("^http://", attr.value.value)
    not regex.match("^https://", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP URL configured instead of HTTPS, allowing interception of sensitive data. (CWE-319)"
    }
}

# Attributes: HTTP URL in Sum (string interpolation)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    sum_contains_http_url(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP URL configured instead of HTTPS, allowing interception of sensitive data. (CWE-319)"
    }
}

# Attributes: protocol: http
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
        "description": "Cleartext transmission of sensitive information - Protocol explicitly set to HTTP instead of HTTPS. (CWE-319)"
    }
}

# Attributes: validate_certs: no
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    lower(attr.name) == "validate_certs"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "no"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled, allowing unencrypted or untrusted connections. (CWE-319)"
    }
}

# Attributes: Hash with protocol: http
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    entry := find_hash_entry(attr.value, "protocol")
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash configuration contains unencrypted HTTP protocol. (CWE-319)"
    }
}

# Attributes: Hash with HTTP URL in any value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    hash_has_http_url(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash contains unencrypted HTTP URL. (CWE-319)"
    }
}

# Attributes: Hash with disabled certificate validation
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    entry := find_hash_entry(attr.value, "validate_certs")
    entry.value.ir_type == "String"
    lower(entry.value.value) == "no"
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled in configuration, allowing unencrypted connections. (CWE-319)"
    }
}

# Variables: HTTP URL in string value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "String"
    regex.match("^http://", var.value.value)
    not regex.match("^https://", var.value.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable assigned with unencrypted HTTP URL, exposing data in transit. (CWE-319)"
    }
}

# Variables: HTTP URL in Sum (string interpolation)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    sum_contains_http_url(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable assigned with unencrypted HTTP URL, exposing data in transit. (CWE-319)"
    }
}

# Variables: Hash with protocol: http - report the specific entry, not the parent var
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    entry := find_hash_entry(var.value, "protocol")
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash contains unencrypted HTTP protocol configuration. (CWE-319)"
    }
}

# Variables: Hash with HTTP URL in any value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    hash_has_http_url(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash contains unencrypted HTTP URL. (CWE-319)"
    }
}

# Variables: Hash with disabled certificate validation - report the specific entry
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    entry := find_hash_entry(var.value, "validate_certs")
    entry.value.ir_type == "String"
    lower(entry.value.value) == "no"
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash disables certificate validation, allowing unencrypted connections. (CWE-319)"
    }
}

# Variables: Hash with disabled encryption - report the specific entry
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    entry := find_hash_entry(var.value, "enforce_https")
    entry.value.ir_type == "Boolean"
    entry.value.value == false
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash disables HTTPS enforcement, allowing unencrypted connections. (CWE-319)"
    }
}