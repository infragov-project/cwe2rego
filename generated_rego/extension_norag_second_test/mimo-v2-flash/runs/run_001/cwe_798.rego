package glitch

import data.glitch_lib

# Define keywords that indicate credential-related fields
credential_keywords := {
    "password", "secret", "key", "token", "credential", "auth",
    "api_key", "access_key", "secret_key", "private_key", "client_secret",
    "passphrase", "ssh_key"
}

# Function to check if a field name is credential-related
is_credential_field(name) {
    lower_name := lower(name)
    contains(lower_name, credential_keywords[_])
}

# Function to check if a value is a hardcoded credential
is_hardcoded_credential(value) {
    value.ir_type == "String"
    value.value != ""
}

# Rule 1: Direct variable assignment with credential-related names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    is_credential_field(var.name)
    is_hardcoded_credential(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials in variable (CWE-798)"
    }
}

# Rule 2: Direct attribute assignment with credential-related names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := glitch_lib.all_attributes(au)[_]
    is_credential_field(attr.name)
    is_hardcoded_credential(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in resource attribute (CWE-798)"
    }
}

# Rule 3: Nested credentials in Hash structures within variables using walk
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    walk(var.value, [path, node])
    node.ir_type == "String"
    count(path) > 0
    last_elem := path[count(path) - 1]
    last_elem.ir_type == "String"
    field_name := last_elem.value
    is_credential_field(field_name)
    is_hardcoded_credential(node)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested configuration (CWE-798)"
    }
}

# Rule 4: Nested credentials in Hash structures within attributes using walk
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := glitch_lib.all_attributes(au)[_]
    walk(attr.value, [path, node])
    node.ir_type == "String"
    count(path) > 0
    last_elem := path[count(path) - 1]
    last_elem.ir_type == "String"
    field_name := last_elem.value
    is_credential_field(field_name)
    is_hardcoded_credential(node)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested resource attribute (CWE-798)"
    }
}

# Rule 5: Attributes within UnitBlock (Puppet-like)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    is_credential_field(attr.name)
    is_hardcoded_credential(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in unit block attribute (CWE-798)"
    }
}