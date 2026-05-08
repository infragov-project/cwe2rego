package glitch

import data.glitch_lib

# Detect cleartext transmission of sensitive information (CWE-319)
# This rule identifies insecure protocols, disabled encryption, and plaintext secrets in IaC

Glitch_Analysis[result] {
    # Gather all unit blocks (Ansible tasks, Chef recipes, Puppet manifests)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes in the unit block
    walk(parent, [path, node])
    
    # Check for insecure protocol usage in String values
    node.ir_type == "String"
    check_insecure_protocol(node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission - Insecure protocol detected (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for disabled encryption in Attribute nodes
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    
    # Check if attribute name indicates encryption settings and value is disabled
    check_disabled_encryption(node.name, node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission - Encryption explicitly disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for plaintext secrets in Variable nodes
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    # Check if variable name indicates sensitive data and value is plaintext
    check_plaintext_secret(node.name, node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission - Plaintext secret detected (CWE-319)"
    }
}

# Helper function to check for insecure protocols
check_insecure_protocol(value) {
    is_string(value)
    regex.match("(?i)^(http://|ftp://|telnet://|smtp://|ldap://)", value)
}

# Helper function to check for disabled encryption in attributes
check_disabled_encryption(name, value) {
    is_string(name)
    regex.match("(?i)(ssl|tls|encrypt|validate_cert|start_tls|require_ssl|https_only)", name)
    value.ir_type == "Boolean"
    value.value == false
}

check_disabled_encryption(name, value) {
    is_string(name)
    regex.match("(?i)(ssl|tls|encrypt|validate_cert|start_tls|require_ssl|https_only)", name)
    value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|disable)$", value.value)
}

# Helper function to check for plaintext secrets
check_plaintext_secret(name, value) {
    is_string(name)
    regex.match("(?i)(password|secret|token|key|credential|auth)", name)
    not is_reference(value)
}

# Helper function to check if value is a reference (e.g., variable, vault)
is_reference(value) {
    value.ir_type == "VariableReference"
}

is_reference(value) {
    value.ir_type == "FunctionCall"
}

is_reference(value) {
    value.ir_type == "String"
    regex.match(".*\\{\\{.*\\}\\}.*", value.value)
}