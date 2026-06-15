package glitch

import data.glitch_lib

# Define insecure patterns for integrity checks
insecure_attributes = {
    "validate_certs", "gpgcheck", "ssl_verify", "checksum", "integrity_check", 
    "hmac", "verify_data", "tls_version", "ssl_policy", "certificate_validation", 
    "mutual_tls", "storage_protocol", "transfer_checksum", "enable_data_validation",
    "api_protocol", "integrity_header", "request_validation", "mode", "source"
}

insecure_values = {
    false, 0, "no", "disabled", "none", "absent", "http", "tlsv1.0", "tlsv1.1", "tlsv1", "0644", "0775"
}

# Check if a value indicates missing integrity
check_insecure_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    value.ir_type == "String"
    insecure_string_values[value.value]
}

insecure_string_values = {
    "no", "disabled", "none", "absent", "http", "tlsv1.0", "tlsv1.1", "tlsv1", "0"
}

# Check for insecure URLs starting with http://
check_insecure_url(value) {
    value.ir_type == "String"
    regex.match("^http://", value.value)
} else {
    # Handle Sum (concatenation) nodes that might form http:// URLs
    value.ir_type == "Sum"
    glitch_lib.traverse(value, "^http://")
}

# Main detection rule for AtomicUnit nodes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Get all attributes from the atomic unit
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure attribute names
    insecure_attributes[attr.name]
    
    # Check for insecure values or URLs
    check_insecure_value(attr.value) or check_insecure_url(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check in IaC configuration - Protocols or configurations lack integrity verification (CWE-353)"
    }
}

# Detection rule for Variable nodes (especially in Ansible YAML)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    
    # Check if the variable value is a Hash (like repository configuration)
    var_node.value.ir_type == "Hash"
    
    # Traverse the hash to find insecure attributes
    walk(var_node.value, [path, attr])
    attr.ir_type == "Attribute"
    insecure_attributes[attr.name]
    check_insecure_value(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check in variable configuration - Repository or data integrity disabled (CWE-353)"
    }
}

# Additional rule for detecting http:// sources in remote resources
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for resource types that might fetch remote content
    node.type == "remote_file" or node.type == "get_url" or node.type == "uri"
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for source/url attributes with http://
    attr.name in {"source", "url", "baseurl"}
    check_insecure_url(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol used for remote resource fetch - HTTP instead of HTTPS (CWE-353)"
    }
}