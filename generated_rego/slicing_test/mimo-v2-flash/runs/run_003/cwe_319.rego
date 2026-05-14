package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find variables with hash values that contain protocol settings
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    hash_pair := node.value.value[_]
    hash_pair.key.ir_type == "String"
    hash_pair.key.value == "protocol"
    hash_pair.value.ir_type == "String"
    
    # Check for insecure protocol values
    insecure_protocols := {"http", "ftp", "telnet", "ws", "tcp", "udp"}
    lower_protocol := lower(hash_pair.value.value)
    lower_protocol == insecure_protocols[_]
    
    result := {
        "type": "sec_https",
        "element": hash_pair.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol setting in configuration (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    value := node.value
    insecure_patterns := {"^http://", "^ftp://", "^telnet://", "^ws://", "^tcp://", "^udp://"}
    pattern := insecure_patterns[_]
    regex.match(pattern, value)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in string (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name := lower(attr.name)
    condition1 := contains(name, "ssl")
    condition2 := contains(name, "cert")
    condition3 := contains(name, "validate")
    any({condition1, condition2, condition3})
    value_node := attr.value
    value_node.ir_type == "String"
    value_node.value == "no"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure certificate validation setting (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name := lower(attr.name)
    condition1 := contains(name, "ssl")
    condition2 := contains(name, "cert")
    condition3 := contains(name, "validate")
    any({condition1, condition2, condition3})
    value_node := attr.value
    value_node.ir_type == "Boolean"
    value_node.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure certificate validation setting (CWE-319)"
    }
}