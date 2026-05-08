package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find Variables directly
    node := glitch_lib.all_variables(parent)[_]
    
    # Check if the variable name indicates a credential
    regex.match("(?i)(password|secret|token|key|credential|auth|passphrase)", node.name)
    
    # Check if value is a non-empty string
    node.value.ir_type == "String"
    node.value.value != ""
    
    # Exclude false positives
    not regex.match("^env\\(.*\\)$", node.value.value)
    not regex.match("^{{.*}}$", node.value.value)
    not regex.match("^\\$[0-9]\\$.*", node.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded credential detected in variable '%s'. (CWE-798)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find Attributes directly
    node := glitch_lib.all_attributes(parent)[_]
    
    # Check if the attribute name indicates a credential
    regex.match("(?i)(password|secret|token|key|credential|auth|passphrase)", node.name)
    
    # Check if value is a non-empty string
    node.value.ir_type == "String"
    node.value.value != ""
    
    # Exclude false positives
    not regex.match("^env\\(.*\\)$", node.value.value)
    not regex.match("^{{.*}}$", node.value.value)
    not regex.match("^\\$[0-9]\\$.*", node.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded credential detected in attribute '%s'. (CWE-798)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Traverse all string nodes in the IR
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    
    # Check if string contains hardcoded credential pattern (e.g., Base64, PEM, URL with credentials)
    # Pattern 1: Base64-encoded string (heuristic: alphanumeric + / + = ending)
    regex.match("^[A-Za-z0-9+/]+={0,2}$", node.value)
    # Only flag if it's likely a key/secret (length > 20 to avoid small strings)
    count(node.value) > 20
    
    # Exclude false positives: URL schemes, file paths, etc.
    not regex.match("^[A-Za-z]+://", node.value)
    not regex.match("^/", node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded cryptographic key material detected (Base64 pattern). (CWE-798)"
    }
}