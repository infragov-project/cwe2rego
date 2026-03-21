package glitch

import data.glitch_lib

insecure_patterns = {
    ["protocol", "http"],
    ["protocol", "ftp"],
    ["protocol", "telnet"],
    ["protocol", "smtp"],
    ["ssl", false],
    ["validate_certs", "no"],
    ["tls_version", "1.0"],
    ["encryption", "none"],
    ["enable_https", false],
    ["force_https", false],
    ["accept_insecure_connections", true]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    key := node.name
    value := node.value.value
    insecure_patterns[pattern]
    pattern[0] == key
    pattern[1] == value
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Insecure configuration detected for cleartext transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key.value
    value := pair.value.value
    insecure_patterns[pattern]
    pattern[0] == key
    pattern[1] == value
    result := {
        "type": "sec_https",
        "element": pair.value,
        "path": parent.path,
        "description": "Insecure configuration detected for cleartext transmission. (CWE-319)"
    }
}