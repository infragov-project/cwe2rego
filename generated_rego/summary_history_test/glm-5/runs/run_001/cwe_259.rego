package glitch

import data.glitch_lib

sensitive_pattern := "^(?i).*(password|passwd|pwd|secret|token|key|credential).*$"
embedded_secret_pattern := "^(?i).*(password|passwd|pwd|secret|token)\\s*=.*$"

is_sensitive_name(name) {
    regex.match(sensitive_pattern, name)
}

is_hardcoded_string(val) {
    val.ir_type == "String"
}

has_embedded_secret(val) {
    is_hardcoded_string(val)
    regex.match(embedded_secret_pattern, val.value)
}

key_name(expr) = name {
    expr.ir_type == "String"
    name = expr.value
}

key_name(expr) = name {
    expr.ir_type == "VariableReference"
    name = expr.value
}

find_secrets_in(node, element) {
    node.ir_type == "Hash"
    pairs := node.value
    pair := pairs[_]
    
    name := key_name(pair.key)
    is_sensitive_name(name)
    is_hardcoded_string(pair.value)
    element := pair.value
}

find_secrets_in(node, element) {
    node.ir_type == "Hash"
    pairs := node.value
    pair := pairs[_]
    
    has_embedded_secret(pair.value)
    element := pair.value
}

find_secrets_in(node, element) {
    node.ir_type == "Hash"
    pairs := node.value
    pair := pairs[_]
    
    find_secrets_in(pair.value, element)
}

find_secrets_in(node, element) {
    node.ir_type == "Array"
    items := node.value
    item := items[_]
    
    has_embedded_secret(item)
    element := item
}

find_secrets_in(node, element) {
    node.ir_type == "Array"
    items := node.value
    item := items[_]
    
    find_secrets_in(item, element)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    
    is_sensitive_name(v.name)
    is_hardcoded_string(v.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded credentials facilitate unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    
    has_embedded_secret(v.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Embedded credentials found. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    
    complex_types := {"Hash", "Array"}
    v.value.ir_type == complex_types[_]
    find_secrets_in(v.value, element)
    
    result := {
        "type": "sec_hard_pass",
        "element": element,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded credentials detected in configuration. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    
    is_sensitive_name(a.name)
    is_hardcoded_string(a.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": a,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded credentials facilitate unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    
    has_embedded_secret(a.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": a,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Embedded credentials found. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    
    complex_types := {"Hash", "Array"}
    a.value.ir_type == complex_types[_]
    find_secrets_in(a.value, element)
    
    result := {
        "type": "sec_hard_pass",
        "element": element,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded credentials detected in configuration. (CWE-259)"
    }
}