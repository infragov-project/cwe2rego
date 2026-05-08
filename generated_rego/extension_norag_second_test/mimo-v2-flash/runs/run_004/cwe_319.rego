package glitch

import data.glitch_lib

contains_insecure_protocol(value_node) {
    walk(value_node, [path, n])
    n.ir_type == "String"
    regex.match("(?i)(http|ftp|telnet|smtp|ldap|smb)://", n.value)
}

is_disabled_encryption_flag(attr) {
    regex.match("(?i)(validate_cert|use_ssl|ssl_enforcement|require_ssl|enable_https|encryption)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(no|false|disabled|off)", attr.value.value)
} else {
    regex.match("(?i)(validate_cert|use_ssl|ssl_enforcement|require_ssl|enable_https|encryption)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
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
        "description": "Insecure protocol used in attribute (CWE-319)"
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
        "description": "Insecure protocol used in variable (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    is_disabled_encryption_flag(attr)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled encryption flag in attribute (CWE-319)"
    }
}