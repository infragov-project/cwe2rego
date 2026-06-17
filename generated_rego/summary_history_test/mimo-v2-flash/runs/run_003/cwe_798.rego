package glitch

import data.glitch_lib

sensitive_pattern := "(?i)(user|username|password|secret|passphrase|token|key|credential|auth|secretValue|credentialBase64|adminPassword|masterKey|sharedKey|connectionString|defaultPassword|initialPassword|loginCredential|encryptionKey|privateKey|secretKey|symmetricKey|apiKey|apiToken|bearerToken|serviceAccountKey|defaultAdmin|rootPassword|guestPassword)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    last_part := regex.split("\\.", var.name)[count(regex.split("\\.", var.name)) - 1]
    regex.match(sensitive_pattern, last_part)
    var.value.ir_type == "String"
    not glitch_lib.traverse_var(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential detected in variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    
    [path, value_node] := walk(var.value)
    value_node.ir_type == "String"
    last_path := path[count(path) - 1]
    last_path.ir_type == "String"
    regex.match(sensitive_pattern, last_path.value)
    not glitch_lib.traverse_var(value_node)
    
    result := {
        "type": "sec_hard_secr",
        "element": value_node,
        "path": parent.path,
        "description": "Hard-coded credential detected. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    regex.match(sensitive_pattern, attr.name)
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential detected in attribute. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    
    [path, value_node] := walk(attr.value)
    value_node.ir_type == "String"
    last_path := path[count(path) - 1]
    last_path.ir_type == "String"
    regex.match(sensitive_pattern, last_path.value)
    not glitch_lib.traverse_var(value_node)
    
    result := {
        "type": "sec_hard_secr",
        "element": value_node,
        "path": parent.path,
        "description": "Hard-coded credential detected. (CWE-798)"
    }
}