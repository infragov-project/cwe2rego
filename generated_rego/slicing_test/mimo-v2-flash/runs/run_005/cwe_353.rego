package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    node.ir_type == "AtomicUnit"

    attrs := glitch_lib.all_attributes(node)

    has_source := false
    has_checksum := false
    source_insecure := false

    attr := attrs[_]
    attr.name == "source"
    has_source := true
    attr.value.ir_type == "String"
    regex.match("^http://", attr.value.value)
    source_insecure := true

    not has_checksum
    not has_source

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure source protocol (http) without integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    node.ir_type == "AtomicUnit"

    attrs := glitch_lib.all_attributes(node)

    attr := attrs[_]
    attr.name == "gpgcheck"
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Package repository integrity check disabled (gpgcheck=0) (CWE-353)"
    }
}