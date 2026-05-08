package glitch

import data.glitch_lib

# Helper to check if a value contains an insecure URL pattern
has_insecure_url(val) {
    walk(val, [_, node])
    node.ir_type == "String"
    regex.match("^(http://|ftp://)", node.value)
}

# Helper to check if a validation attribute is disabled
is_validation_disabled(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "String"
    lower(val.value) == "no"
} else {
    val.ir_type == "Integer"
    val.value == 0
}

# Detect insecure URLs in Ansible/Chef attributes (e.g., source, url)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure URLs in relevant attributes
    url_attributes := {"url", "source", "baseurl"}
    attr.name == url_attributes[_]
    has_insecure_url(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Integrity Check - Insecure protocol used (CWE-353)"
    }
}

# Detect disabled validation in Ansible (e.g., validate_certs: no)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for validation attributes
    validation_attributes := {"validate_certs", "ssl_verify", "verify_ssl", "gpgcheck"}
    attr.name == validation_attributes[_]
    is_validation_disabled(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Integrity Check - Validation disabled (CWE-353)"
    }
}

# Detect insecure URLs in Ansible variables (e.g., epel_mirror_baseurl)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in the unit block
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable name suggests it's a URL/baseurl
    url_var_pattern := "(?i).*(url|baseurl|mirror).*"
    regex.match(url_var_pattern, var.name)
    
    # Check if the value contains an insecure URL
    has_insecure_url(var.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing Integrity Check - Insecure URL in variable (CWE-353)"
    }
}