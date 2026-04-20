package glitch

import data.glitch_lib

insecure_url_pattern := "(?i)^http://"
insecure_attr_names := {"validate_certs", "tls", "ssl", "checksum", "signature", "hmac", "source", "url", "baseurl"}
insecure_attr_values := {false, "no", "disabled", "false"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    glitch_lib.traverse(node, insecure_url_pattern)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure HTTP URL used without integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in insecure_attr_names
    glitch_lib.traverse(attr, insecure_attr_values)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity check explicitly disabled or missing. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    glitch_lib.traverse(node, insecure_url_pattern)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Variable contains insecure HTTP URL without integrity checks. (CWE-353)"
    }
}