package glitch

import data.glitch_lib

password_attr_exact := {"password", "passwd", "pwd", "secret", "credentials", "auth_token", "api_key", "private_key", "initial_password", "admin_password", "root_password", "default_password", "keystore_password", "truststore_password", "sha512_password", "key"}

password_attr_suffixes := {"_password", "_secret", "_key", "_token", "_credentials"}

is_password_attr(name) {
    lower_name := lower(name)
    password_attr_exact[lower_name]
}

is_password_attr(name) {
    lower_name := lower(name)
    endswith(lower_name, password_attr_suffixes[_])
}

is_password_attr(name) {
    lower_name := lower(name)
    contains(lower_name, "_password_")
}

contains_password_in_brackets(name) {
    parts := split(name, "[")
    some i
    i > 0
    part := parts[i]
    trimmed := trim(part, "'\"]")
    is_password_attr(trimmed)
}

is_credential_key(name) {
    lower_name := lower(name)
    lower_name == "key"
}

is_credential_context(path) {
    count(path) > 0
    parent_key := path[count(path) - 1]
    lower_parent := lower(parent_key)
    lower_parent == "cvauth"
}

is_safe_pattern(val) {
    regex.match(".*\\$\\{.*\\}.*", val)
}

is_safe_pattern(val) {
    regex.match(".*\\$[a-zA-Z_][a-zA-Z0-9_]*", val)
    not regex.match("^\\$[0-9]", val)
}

is_safe_pattern(val) {
    regex.match("^::[a-zA-Z_].*$", val)
}

is_safe_pattern(val) {
    regex.match(".*\\bdata\\..*", val)
}

is_safe_pattern(val) {
    regex.match(".*\\blookup\\b.*", lower(val))
}

is_safe_pattern(val) {
    regex.match(".*\\bvault_.*", lower(val))
}

is_safe_pattern(val) {
    regex.match(".*\\bget_secret\\b.*", lower(val))
}

is_path_value(val) {
    regex.match("^[\\./].*", val)
}

is_path_value(val) {
    regex.match("^[a-zA-Z]:\\\\", val)
}

is_path_value(val) {
    regex.match("^conf/", val)
}

is_path_value(val) {
    endswith(lower(val), ".keystore")
}

is_path_value(val) {
    endswith(lower(val), ".p12")
}

is_path_value(val) {
    endswith(lower(val), ".jks")
}

is_path_value(val) {
    endswith(lower(val), ".truststore")
}

is_hardcoded_string_value(node) {
    node.ir_type == "String"
    val := node.value
    val != ""
    not is_safe_pattern(val)
    not is_path_value(val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some k
    node.value[k]
    kv := node.value[k]
    kv.key.ir_type == "String"
    key_name := kv.key.value
    is_password_attr(key_name)
    is_hardcoded_string_value(kv.value)
    result := {
        "type": "sec_hard_pass",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hardcoded password in nested Hash value. Use secure secret management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some k
    node.value[k]
    kv := node.value[k]
    kv.key.ir_type == "String"
    key_name := kv.key.value
    is_credential_key(key_name)
    is_credential_context(path)
    is_hardcoded_string_value(kv.value)
    result := {
        "type": "sec_hard_pass",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hardcoded authentication key in credential context. Use secure secret management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    is_hardcoded_string_value(node)
    val := node.value
    parts := split(val, "=")
    count(parts) > 1
    key_name := parts[0]
    is_password_attr(key_name)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hardcoded password in key=value string. Use secure secret management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    is_password_attr(vars.name)
    is_hardcoded_string_value(vars.value)
    result := {
        "type": "sec_hard_pass",
        "element": vars,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password hardcoded in variable with credential-related name. Use secure secret management instead of hardcoded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    contains_password_in_brackets(vars.name)
    is_hardcoded_string_value(vars.value)
    result := {
        "type": "sec_hard_pass",
        "element": vars,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password hardcoded in Chef bracket-style variable. Use secure secret management instead of hardcoded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    var_name := vars.name
    parts := split(var_name, ".")
    some i
    part := parts[i]
    is_password_attr(part)
    is_hardcoded_string_value(vars.value)
    result := {
        "type": "sec_hard_pass",
        "element": vars,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password hardcoded in Chef/Puppet dotted variable name. Use secure secret management instead of hardcoded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    walk(cond, [path, node])
    node.ir_type == "Variable"
    is_password_attr(node.name)
    is_hardcoded_string_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password hardcoded in conditional statement variable. Use secure secret management instead of hardcoded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    walk(cond, [path, node])
    node.ir_type == "Variable"
    contains_password_in_brackets(node.name)
    is_hardcoded_string_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password hardcoded in Chef bracket-style conditional variable. Use secure secret management instead of hardcoded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    walk(cond, [path, node])
    node.ir_type == "Variable"
    var_name := node.name
    parts := split(var_name, ".")
    some i
    part := parts[i]
    is_password_attr(part)
    is_hardcoded_string_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password hardcoded in conditional variable with dotted credential name. Use secure secret management instead of hardcoded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_password_attr(attr.name)
    is_hardcoded_string_value(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hardcoded password in attribute value. Use secure secret management instead. (CWE-259)"
    }
}