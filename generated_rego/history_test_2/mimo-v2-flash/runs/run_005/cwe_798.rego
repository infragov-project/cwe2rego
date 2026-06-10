package glitch

import data.glitch_lib

hardcoded_credential_keywords := {"password", "secret", "key", "token", "credential", "api_key", "auth", "pass", "passwd", "secret_key", "access_key", "private_key", "cvauth", "sha512_password"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables in the parent block
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check variable name for credential keywords (case-insensitive)
    var_name_lower := lower(var.name)
    some keyword in hardcoded_credential_keywords
    contains(var_name_lower, keyword)
    
    # Check if the value is a static string (not a reference)
    var.value.ir_type == "String"
    not glitch_lib.traverse_var(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all attributes in the parent block
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check attribute name for credential keywords (case-insensitive)
    attr_name_lower := lower(attr.name)
    some keyword in hardcoded_credential_keywords
    contains(attr_name_lower, keyword)
    
    # Check if the value is a static string (not a reference)
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all attributes in the parent block
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute value is a Hash containing credential keywords
    attr.value.ir_type == "Hash"
    
    # Recursively check nested hash for credential keys with static values
    check_hash_for_credentials(attr.value, credentials)
    credentials != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in code. (CWE-798)"
    }
}

check_hash_for_credentials(hash_val, credentials) {
    some key_value in hash_val.value
    key_value.key.ir_type == "String"
    key_name_lower := lower(key_value.key.value)
    some keyword in hardcoded_credential_keywords
    contains(key_name_lower, keyword)
    
    # Check if the value is a static string
    key_value.value.ir_type == "String"
    not glitch_lib.traverse_var(key_value.value)
    
    credentials := "found"
}

check_hash_for_credentials(hash_val, credentials) {
    some key_value in hash_val.value
    key_value.value.ir_type == "Hash"
    check_hash_for_credentials(key_value.value, nested_credentials)
    nested_credentials != ""
    credentials := "found"
}