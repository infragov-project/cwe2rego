package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Collect all attributes from the parent unit block
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    # Detect: validate_certs set to no/false (insecure SSL/TLS validation)
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    lower_case := lower(attr.value.value)
    (lower_case == "no") or (lower_case == "false")
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure TLS/SSL certificate validation disabled - This may allow man-in-the-middle attacks. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Detect protocol set to http in variables or attributes
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    attr.name == "protocol"
    attr.value.ir_type == "String"
    lower_case := lower(attr.value.value)
    lower_case == "http"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext protocol (HTTP) used for data transmission - Sensitive data may be exposed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Detect URLs starting with http:// in String values
    all_values := {n |
        walk(parent, [path, n])
        n.ir_type == "String"
    }
    str_val := all_values[_]
    
    regex.match(`^http://`, str_val.value)
    
    result := {
        "type": "sec_https",
        "element": str_val,
        "path": parent.path,
        "description": "Cleartext URL (http://) used for data transmission - Sensitive data may be exposed. (CWE-319)"
    }
}