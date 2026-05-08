package glitch

import data.glitch_lib

weak_algorithms := {"md5", "sha1", "des", "rc4", "blowfish", "aes-ecb", "rc2", "md2", "md4", "rsa-1024", "dsa", "md5_crypt"}
risky_modes := {"ecb", "cbc"}

contains_weak_string(node) {
    walk(node, [path, n])
    n.ir_type == "String"
    lower_value := lower(n.value)
    some weak in weak_algorithms
    contains(lower_value, weak)
}

contains_weak_string(node) {
    walk(node, [path, n])
    n.ir_type == "String"
    lower_value := lower(n.value)
    some mode in risky_modes
    contains(lower_value, mode)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_weak_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or risky mode (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_weak_string(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or risky mode (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    contains_weak_string(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or risky mode (CWE-327)"
    }
}