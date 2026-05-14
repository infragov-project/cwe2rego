package glitch

import data.glitch_lib

# Detect insecure protocols (http://) in source or url attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "source"
    attr.value.ir_type == "String"
    regex.match("(?i)^http://", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Using insecure HTTP protocol for resource download. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "url"
    attr.value.ir_type == "String"
    regex.match("(?i)^http://", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Using insecure HTTP protocol for resource download. (CWE-353)"
    }
}