package glitch

import data.glitch_lib

sensitive_key_pattern := "(password|secret|token|credential|auth|passwd|pwd|apikey|accesskey|secretkey|private_key|client_secret|truststore_password|keystore_password|secret_uuid|key|user|username)"

is_hardcoded_string(value) {
    value.ir_type == "String"
    not glitch_lib.has_variable_reference(value)
}

is_sensitive(key) {
    regex.match(sensitive_key_pattern, key)
}

# Check Variables (like Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_sensitive(var.name)
    is_hardcoded_string(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in code. (CWE-798)"
    }
}

# Check Attributes (like Ansible variables and Puppet parameters)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    is_sensitive(attr.name)
    is_hardcoded_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in code. (CWE-798)"
    }
}

# Check Hash key-value pairs (including nested hashes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "String"
    is_sensitive(kv.key.value)
    is_hardcoded_string(kv.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in code. (CWE-798)"
    }
}

# Check Conditional Statements for assignments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    
    # Check variables inside conditional statements
    walk(cond, [path, node])
    node.ir_type == "Variable"
    is_sensitive(node.name)
    is_hardcoded_string(node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in code. (CWE-798)"
    }
}

# Check Conditional Statements for attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    
    # Check attributes inside conditional statements
    walk(cond, [path, node])
    node.ir_type == "Attribute"
    is_sensitive(node.name)
    is_hardcoded_string(node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in code. (CWE-798)"
    }
}