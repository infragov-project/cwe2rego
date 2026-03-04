package glitch

import data.glitch_lib

insecure_protocol_pattern := "^(?i)(http|ftp|telnet|smtp|ldap)://"

contains_insecure_protocol(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match(insecure_protocol_pattern, n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    contains_insecure_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of unencrypted communication protocol - Data transmitted over unencrypted channels can be intercepted. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    contains_insecure_protocol(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Variable assigned unencrypted protocol - Data transmitted over unencrypted channels can be intercepted. (CWE-319)"
    }
}