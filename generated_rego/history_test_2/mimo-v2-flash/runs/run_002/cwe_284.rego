package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := {n | walk(parent, [path, n]); n.ir_type == "String"; regex.match("^0\\.0\\.0\\.0$", n.value)}
    node := nodes[_]
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Resource configured to bind to all IP addresses (0.0.0.0), allowing unauthorized access. (CWE-284)"
    }
}