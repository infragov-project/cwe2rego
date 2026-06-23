package glitch

import data.glitch_lib
import future.keywords.if
import future.keywords.in

credential_keywords := {"password", "pwd", "passwd", "secret", "_secret", "token", "api_key", "apikey", "access_key", "secret_key", "private_key", "credential", "auth_token", "jwt", "bearer", "sha512_", "sha256_", "key"}

# Check if string contains any credential keyword (substring match)
has_credential_keyword(name) if {
    lower_name := lower(name)
    some kw in credential_keywords
    contains(lower_name, kw)
}

# Check if a node or any of its sub-nodes is a VariableReference
is_variable_ref(node) if {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
}

# Check if value is a literal string (not variable ref)
is_literal_string(node) if {
    node.ir_type == "String"
    not is_variable_ref(node)
}

# Recursively find all credential string values in any value structure
# Uses walk to traverse deeply nested structures
find_credentials(val) = {{key: k, value: v} |
    walk(val, [path, node])
    node.ir_type == "String"
    count(path) > 0
    parent := path[count(path) - 1]
    parent.ir_type == "Hash"
    some entry in parent.value
    entry.key.ir_type == "String"
    entry.value == node
    k := entry.key.value
    has_credential_keyword(k)
    v := node
}

# Case 1: Variable name contains credential keyword with String value
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some var in parent.variables
    var.ir_type == "Variable"
    has_credential_keyword(var.name)
    is_literal_string(var.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": var.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in variables. Use secret management instead. (CWE-798)"
    }
}

# Case 2: Nested credentials within Hash structures in variables
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some var in parent.variables
    var.ir_type == "Variable"
    creds := find_credentials(var.value)
    count(creds) > 0
    some cred in creds
    not is_variable_ref(cred.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in variables. Use secret management instead. (CWE-798)"
    }
}

# Case 3: Atomic unit attribute name contains credential keyword with String value
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    has_credential_keyword(attr.name)
    is_literal_string(attr.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in resource attributes. Use secret management instead. (CWE-798)"
    }
}

# Case 4: Nested credentials within Hash structures in atomic unit attributes
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    creds := find_credentials(attr.value)
    count(creds) > 0
    some cred in creds
    not is_variable_ref(cred.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in resource attributes. Use secret management instead. (CWE-798)"
    }
}

# Case 5: Arrays containing values with credentials in variables
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some var in parent.variables
    var.ir_type == "Variable"
    var.value.ir_type == "Array"
    
    some elem in var.value.value
    creds := find_credentials(elem)
    count(creds) > 0
    some cred in creds
    not is_variable_ref(cred.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in variables. Use secret management instead. (CWE-798)"
    }
}

# Case 6: Arrays containing values with credentials in atomic units
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    
    some elem in attr.value.value
    creds := find_credentials(elem)
    count(creds) > 0
    some cred in creds
    not is_variable_ref(cred.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in resource attributes. Use secret management instead. (CWE-798)"
    }
}

# Case 7: Direct hash values in unit blocks (for deeply nested Ansible vars)
Glitch_Analysis[res] if {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some attr in parent.attributes
    attr.ir_type == "Attribute"
    
    has_credential_keyword(attr.name)
    is_literal_string(attr.value)
    
    res := {
        "type": "sec_hard_secr",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in attributes. Use secret management instead. (CWE-798)"
    }
}