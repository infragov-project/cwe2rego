package glitch

import data.glitch_lib

# Helper to check if a value contains an insecure protocol (http/ftp)
contains_insecure_protocol(val) {
    walk(val, [_, leaf])
    leaf.ir_type == "String"
    regex.match("^(http|ftp)://", leaf.value)
}

# Helper to check for integrity validation attributes
has_integrity_validation(attrs) {
    attr := attrs[_]
    attr.name == "checksum"
} else {
    attr := attrs[_]
    attr.name == "sha256"
} else {
    attr := attrs[_]
    attr.name == "gpgcheck"
    attr.value.ir_type == "Integer"
    attr.value.value == 1
} else {
    attr := attrs[_]
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
} else {
    attr := attrs[_]
    attr.name == "validate_certs"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

# Rule 1: Detect insecure transport in download modules
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Match specific module names or patterns
    node.type == "get_url"
    
    attrs := glitch_lib.all_attributes(node)
    url_attr := attrs[_]
    url_attr.name == "url"
    
    # Check for insecure protocol
    contains_insecure_protocol(url_attr.value)
    
    # Check if integrity validation is missing
    not has_integrity_validation(attrs)
    
    result := {
        "type": "sec_no_int_check",
        "element": url_attr,
        "path": parent.path,
        "description": "Insecure protocol used for download without integrity validation (CWE-353)"
    }
}

# Rule 2: Detect insecure repository URLs in Ansible variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Walk to find Hash nodes (representing repository configs)
    walk(var.value, [path, n])
    n.ir_type == "Hash"
    
    repo_attrs := glitch_lib.all_attributes(n)
    baseurl_attr := repo_attrs[_]
    baseurl_attr.name == "baseurl"
    
    # Check for insecure protocol in the baseurl
    contains_insecure_protocol(baseurl_attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": baseurl_attr,
        "path": parent.path,
        "description": "Insecure repository baseurl (HTTP) used without integrity validation (CWE-353)"
    }
}

# Rule 3: Detect insecure source URLs in Chef remote_file
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    
    attrs := glitch_lib.all_attributes(node)
    source_attr := attrs[_]
    source_attr.name == "source"
    
    # Check for insecure protocol in the source URL
    contains_insecure_protocol(source_attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": source_attr,
        "path": parent.path,
        "description": "Insecure source URL used without integrity validation (CWE-353)"
    }
}