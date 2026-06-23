package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "pwd", "secret", "credentials", "auth_token", "pass", "sha512_password", "sha256_password", "key", "token", "api_key", "secret_key", "access_key"}

# Check if name contains credential keyword (exact match or word boundary)
is_credential_name(name) {
    lname := lower(name)
    some keyword
    password_keywords[keyword]
    lname == keyword
}

is_credential_name(name) {
    lname := lower(name)
    some keyword
    password_keywords[keyword]
    endswith(lname, concat("", ["_", keyword]))
}

is_credential_name(name) {
    lname := lower(name)
    some keyword
    password_keywords[keyword]
    startswith(lname, concat("", [keyword, "_"]))
}

# Check if this is a secure reference (not hard-coded)
is_secure_reference(value) {
    value.ir_type == "String"
    regex.match("^\\$\\{|.*(vault|secret|lookup|env|var|data|file|template|key)\\s*\\(|^(variable|var|local|data|module|path)\\.", value.value)
}

is_secure_reference(value) {
    value.ir_type == "VariableReference"
}

is_secure_reference(value) {
    value.ir_type == "FunctionCall"
    regex.match(".*(vault|secret|lookup|file|template|env)", value.name)
}

# Check if value is a hard-coded credential
is_hardcoded_credential(value) {
    value.ir_type == "String"
    not is_secure_reference(value)
    value.value != ""
    not regex.match("^\\$[0-9a-zA-Z]+\\$", value.value)
}

# Extract key string from Hash entry structure (Ansible-style with key/value)
get_key_string(entry) = key_str {
    entry.key.ir_type == "String"
    key_str := entry.key.value
}

# Check if string contains credential pattern like KEY=password
string_contains_credential(str) = result {
    parts := split(str, "=")
    count(parts) >= 2
    key_part := parts[0]
    is_credential_name(key_part)
    result := parts[count(parts) - 1]
}

# Walk and find credentials in any structure
find_hardcoded_credential(node) = result {
    walk(node, [_, item])
    item.ir_type == "String"
    is_hardcoded_credential(item)
    
    # Check if this string is a KEY=value pattern with credential key
    cred_value := string_contains_credential(item.value)
    result := {
        "value": item,
        "cred_value": cred_value
    }
}

# Find credentials in Hash entries (Ansible-style nested structures)
find_credential_in_hash_deep(node) = result {
    walk(node, [_, item])
    item.ir_type == "Hash"
    walk(item.value, [_, entry])
    entry.key.ir_type == "String"
    entry.value
    key_str := get_key_string(entry)
    is_credential_name(key_str)
    is_hardcoded_credential(entry.value)
    result := entry.value
}

# Recursively find all hash-like structures and check their entries
find_all_credentials(node) = result {
    # Direct hash entry pattern (Python KeyValue or Ansible dict entry)
    results := {r |
        walk(node, [_, entry])
        entry.key
        entry.value
        key_str := get_key_string(entry)
        is_credential_name(key_str)
        is_hardcoded_credential(entry.value)
        r := entry.value
    }
    count(results) > 0
    result := results[_]
}

# Check array elements for KEY=value credential patterns
find_credential_in_array(node) = result {
    walk(node, [_, item])
    item.ir_type == "Array"
    walk(item.value, [_, elem])
    elem.ir_type == "String"
    is_hardcoded_credential(elem)
    string_contains_credential(elem.value)
    result := elem
}

# Main analysis - Chef/Puppet style dotted variable names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := {v |
        walk(parent, [_, v])
        v.ir_type == "Variable"
    }
    var := vars[_]
    
    is_credential_name(var.name)
    is_hardcoded_credential(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}

# Main analysis - direct credential attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := {a |
        walk(parent, [_, a])
        a.ir_type == "Attribute"
    }
    attr := attrs[_]
    
    is_credential_name(attr.name)
    is_hardcoded_credential(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}

# Main analysis - nested credential keys in variables (deep search)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := {v |
        walk(parent, [_, v])
        v.ir_type == "Variable"
    }
    var := vars[_]
    
    violation := find_all_credentials(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": violation,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}

# Main analysis - nested credential keys in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    violation := find_all_credentials(au)
    
    result := {
        "type": "sec_hard_pass",
        "element": violation,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}

# Handle KeyValue within Attribute values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := {a |
        walk(parent, [_, a])
        a.ir_type == "Attribute"
    }
    attr := attrs[_]
    
    walk(attr.value, [_, kv])
    kv.ir_type == "KeyValue"
    is_credential_name(kv.name)
    is_hardcoded_credential(kv.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}

# Handle Puppet-style env arrays with KEY=value strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, item])
    item.ir_type == "String"
    is_hardcoded_credential(item)
    string_contains_credential(item.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": item,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}

# Handle complex nested structures in arrays (Puppet env attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    
    walk(attr.value, [_, arr])
    arr.ir_type == "Array"
    
    walk(arr.value, [_, elem])
    elem.ir_type == "String"
    is_hardcoded_credential(elem)
    string_contains_credential(elem.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": elem,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be embedded directly in code. Use secure credential management systems. (CWE-259)"
    }
}