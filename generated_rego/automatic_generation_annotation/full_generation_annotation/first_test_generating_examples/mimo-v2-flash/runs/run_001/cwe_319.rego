package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "url"
    attr.value.ir_type == "String"
    startswith(attr.value.value, "http://")

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted URL - URL uses HTTP protocol instead of HTTPS (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "source"
    attr.value.ir_type == "String"
    startswith(attr.value.value, "http://")

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted Source - Source URL uses HTTP protocol instead of HTTPS (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "command"
    attr.value.ir_type == "String"
    contains(attr.value.value, "http://")

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted Command - Command execution contains HTTP URL (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "content"
    attr.value.ir_type == "String"
    contains(attr.value.value, "http://")

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted Content - Configuration file content contains HTTP URL (CWE-319)"
    }
}