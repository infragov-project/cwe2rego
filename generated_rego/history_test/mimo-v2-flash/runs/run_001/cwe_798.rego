package glitch

import data.glitch_lib

sensitive_keywords := "(?i)password|secret|token|key|credential|auth|passphrase|admin_password|db_password|api_key|private_key|secret_key|ssh_key|encryption_key|signing_key|certificate|keystore_password"

check_sensitive_value(value) {
    value.ir_type == "String"
    regex.match(sensitive_keywords, value.value)
}

check_sensitive_value(value) {
    value.ir_type == "Hash"
    check_hash_sensitive(value)
}

check_hash_sensitive(hash) {
    some kv in hash.value
    key_string := kv.key.value
    regex.match(sensitive_keywords, key_string)
    kv.value.ir_type == "String"
} else {
    some kv in hash.value
    kv.value.ir_type == "Hash"
    check_hash_sensitive(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    check_sensitive_value(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential found in variable - CWE-798"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    check_sensitive_value(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential found in attribute - CWE-798"
    }
}