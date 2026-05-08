package glitch

import data.glitch_lib

# 1. Definition of password-related keywords (case-insensitive)
password_keywords = {"password", "pwd", "secret", "token", "passphrase", "credential"}

# 2. Helper to check if a value is effectively empty
is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "String"
    trim(value.value, " ") == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

# 3. Helper to check if a name contains a password-related keyword
is_password_field(name) {
    name_lower := lower(name)
    some kw
    kw = password_keywords[_]
    contains(name_lower, kw)
}

# 4. Rule: Direct Empty Assignment in Variables/Attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Get all key-value pairs (variables, attributes, or parameters)
    # In Chef/Puppet, these are often represented as Variable or Attribute in the IR
    all_keyvalues := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    kv := all_keyvalues[_]

    # Check if the key name contains password-related keywords
    is_password_field(kv.name)

    # Check if the value is empty
    is_empty_value(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration - A password field is set to an empty value. (CWE-258)"
    }
}

# 5. Rule: Empty password in connection strings or string values containing credentials
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Look at attributes that might contain connection strings or credential strings
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    # Check if the attribute value is a string
    attr.value.ir_type == "String"

    # Check if the string contains a password pattern with empty value
    # Regex matches: password=; or password=& or password= followed by end of string/whitespace
    regex.match("(?i)(password|pwd|secret|token)\\s*=\\s*([;&\\s]|$)", attr.value.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string or configuration string. (CWE-258)"
    }
}

# 6. Rule: Nested Hash/Array containing empty password fields
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Get all variables (which might contain complex values)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    # Recursively check complex values for empty passwords
    walk(var.value, [path, node])
    node.ir_type == "Attribute"
    is_password_field(node.name)
    is_empty_value(node.value)

    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in nested configuration structure. (CWE-258)"
    }
}