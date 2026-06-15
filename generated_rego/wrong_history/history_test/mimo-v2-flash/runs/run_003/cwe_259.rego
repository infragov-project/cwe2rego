package glitch

import data.glitch_lib

# Define patterns for sensitive property names (case-insensitive)
sensitive_patterns := {"password", "secret", "token", "key", "credential", "auth"}

# Check if a string value matches a hard-coded pattern (not a variable reference)
is_hardcoded_string(value) {
    value.ir_type == "String"
    # Check if the value is not a placeholder or variable-like
    not regex.match("^(?i)(vault|env|var|reference|lookup|secret)", value.value)
}

# Check if a property name indicates sensitivity
is_sensitive_property(name) {
    is_string(name)
    lower_name := lower(name)
    some pattern
    sensitive_patterns[pattern]
    contains(lower_name, pattern)
}

# Recursive search for sensitive key-value pairs in complex structures
find_sensitive_pairs(node, path, result) {
    walk(node, [path, n])
    n.ir_type == "Hash"
    pair := n.value[_]
    key := pair.key
    value := pair.value
    is_sensitive_property(key.value)
    is_hardcoded_string(value)
    result := {
        "element": value,
        "path": input.path,
        "description": "Hard-coded password detected in configuration - CWE-259"
    }
} else {
    walk(node, [path, n])
    n.ir_type == "Array"
    item := n.value[_]
    find_sensitive_pairs(item, path, result)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    # Check variables (e.g., Ansible variables, Chef attributes)
    variable := parent.variables[_]
    # For variables, check if the name indicates sensitivity (e.g., "default.sensu.rabbitmq.password")
    is_sensitive_property(variable.name)
    is_hardcoded_string(variable.value)
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Hard-coded password in variable - CWE-259"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    # Check attributes (e.g., resource attributes in IaC)
    attribute := parent.attributes[_]
    is_sensitive_property(attribute.name)
    is_hardcoded_string(attribute.value)
    result := {
        "type": "sec_hard_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Hard-coded password in attribute - CWE-259"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    # Check for hard-coded passwords in complex structures (Hash/Array)
    find_sensitive_pairs(parent, [], result)
}