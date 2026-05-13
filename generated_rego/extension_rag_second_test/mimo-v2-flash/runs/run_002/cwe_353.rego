package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    walk(attr.value, [path, n])
    n.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|tcp://|udp://)", n.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Protocol lacks built-in integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    (attr.name == "validate_certs" or attr.name == "verify_ssl" or attr.name == "ssl_verify")
    attr.value.ir_type == "String"
    (attr.value.value == "no" or attr.value.value == "false" or attr.value.value == "0")
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Certificate validation disabled (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    (attr.name == "gpgcheck" or attr.name == "checksum" or attr.name == "verify_checksum")
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - GPG/checksum validation disabled (CWE-353)"
    }
}