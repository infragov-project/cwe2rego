package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted communication channel detected - Use of plaintext protocol for sensitive data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "secure_transfer_required"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled encryption setting detected - Encryption explicitly disabled for data-in-transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "secure_transfer_required"
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "false"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled encryption setting detected - Encryption explicitly disabled for data-in-transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "secure_transfer_required"
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "disabled"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled encryption setting detected - Encryption explicitly disabled for data-in-transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "secure_transfer_required"
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "none"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled encryption setting detected - Encryption explicitly disabled for data-in-transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "secure_transfer_required"
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "not_required"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled encryption setting detected - Encryption explicitly disabled for data-in-transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "port"
    attr.value.ir_type == "String"
    attr.value.value == "80"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol configuration detected - Service configured to listen on HTTP port 80 without SSL/TLS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "port"
    attr.value.ir_type == "Integer"
    attr.value.value == 80
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol configuration detected - Service configured to listen on HTTP port 80 without SSL/TLS. (CWE-319)"
    }
}