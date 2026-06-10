package glitch

import data.glitch_lib

broken_algorithm_pattern := "(?i)\\b(md5|sha1|des|3des|rc4|blowfish|tea|xor|ssl3|tls1[._]?0|tls1[._]?1|ecb)\\b"

check_for_broken_crypto(node) {
    glitch_lib.traverse(node, broken_algorithm_pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    check_for_broken_crypto(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    check_for_broken_crypto(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}