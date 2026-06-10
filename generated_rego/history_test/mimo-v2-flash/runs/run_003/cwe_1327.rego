package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables (Ansible, etc.)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Match variable names that suggest binding addresses (general pattern)
    regex.match("(?i).*(bind|listen|address|ip|host|server|endpoint).*", var.name)
    
    # Check if the value is 0.0.0.0
    var.value.ir_type == "String"
    var.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (CWE-1327) - Variable set to 0.0.0.0"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Attributes (Atomic Units)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Match attribute names that suggest binding addresses
    regex.match("(?i).*(bind|listen|address|ip|host|server|endpoint).*", attr.name)
    
    # Check if the value is 0.0.0.0
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (CWE-1327) - Attribute set to 0.0.0.0"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Hash entries (Chef, etc.) - looking for key-value pairs within Hash values
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Iterate through hash entries
    entry := node.value[_]
    
    # Check if the key suggests an IP/binding attribute
    key_name := entry.key.value
    regex.match("(?i).*(bind|listen|address|ip|host|server|endpoint).*", key_name)
    
    # Check if the value is 0.0.0.0
    entry.value.ir_type == "String"
    entry.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (CWE-1327) - Hash entry set to 0.0.0.0"
    }
}