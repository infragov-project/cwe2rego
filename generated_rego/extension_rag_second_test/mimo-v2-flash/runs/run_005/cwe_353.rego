package glitch

import data.glitch_lib

insecure_protocols := {"http://", "ftp://"}
integrity_disabled_flags := {"no", "false", "0", "none"}
security_keywords := {"validate_certs", "gpgcheck", "verify", "check", "ssl", "tls", "encryption", "integrity", "checksum"}

# Check if a node contains an insecure URL
is_insecure_url(node) {
    node.ir_type == "String"
    some protocol
    insecure_protocols[protocol]
    contains(node.value, protocol)
}

# Check if a node represents a disabled integrity check
is_integrity_disabled(node) {
    node.ir_type == "String"
    some flag
    integrity_disabled_flags[flag]
    lower(node.value) == flag
} else {
    node.ir_type == "Boolean"
    node.value == false
} else {
    node.ir_type == "Integer"
    node.value == 0
}

# Rule 1: Detect insecure URLs in attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent (including nested ones)
    walk(parent, [_, attr_node])
    attr_node.ir_type == "Attribute"
    
    # Check if attribute name suggests URL or source
    regex.match("^(url|source|baseurl|mirrorlist)$", attr_node.name)
    
    # Walk through the attribute value to find insecure URL
    walk(attr_node.value, [_, value_node])
    is_insecure_url(value_node)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr_node,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used in URL (CWE-353)"
    }
}

# Rule 2: Detect disabled integrity checks in attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent (including nested ones)
    walk(parent, [_, attr_node])
    attr_node.ir_type == "Attribute"
    
    # Check if attribute name suggests security/integrity check
    regex.match("^(validate_certs|gpgcheck|verify|check|ssl|tls|encryption|integrity|checksum)$", attr_node.name)
    
    # Walk through the attribute value to find disabled flags
    walk(attr_node.value, [_, value_node])
    is_integrity_disabled(value_node)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr_node,
        "path": parent.path,
        "description": "Integrity check disabled (CWE-353)"
    }
}

# Rule 3: Detect insecure URLs in variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent
    walk(parent, [_, var_node])
    var_node.ir_type == "Variable"
    
    # Walk through the variable value to find insecure URL
    walk(var_node.value, [_, value_node])
    is_insecure_url(value_node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var_node,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used in variable (CWE-353)"
    }
}

# Rule 4: Detect disabled integrity checks in variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent
    walk(parent, [_, var_node])
    var_node.ir_type == "Variable"
    
    # Check if variable name suggests security/integrity
    regex.match("(?i)(validate|gpg|verify|check|ssl|tls|encryption|integrity|checksum)", var_node.name)
    
    # Walk through the variable value to find disabled flags
    walk(var_node.value, [_, value_node])
    is_integrity_disabled(value_node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var_node,
        "path": parent.path,
        "description": "Integrity check disabled in variable (CWE-353)"
    }
}