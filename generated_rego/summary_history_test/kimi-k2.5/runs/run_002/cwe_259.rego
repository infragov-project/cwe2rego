package glitch

import data.glitch_lib
import future.keywords.in

credential_keywords := {"password", "pwd", "pass", "secret", "auth_token", "credential", "keystore_password", "truststore_password", "key", "token", "auth", "passwd", "sha512_password", "sha256_password", "md5_password"}

default_passwords := {"admin", "password", "123456", "default", "changeme", "root", "toor", "guest", "user", "test", "password123", "admin123", "12345678", "qwerty", "letmein", "welcome", "login", "pass", "cassandra", "telarista"}

is_external_reference(str) {
    regex.match("\\$\\{", str)
}

is_external_reference(str) {
    regex.match("(?i)secret|vault|keyvault|key.?manager|data\\.", str)
}

is_variable_reference(str) {
    regex.match("\\$\\(|\\$\\{|\\$[a-zA-Z_]|\\$\\$", str)
}

is_credential_attribute(name) {
    lower_name := lower(name)
    some kw in credential_keywords
    regex.match(sprintf(".*%s.*", [kw]), lower_name)
}

is_default_password(val_str) {
    lower_val := lower(val_str)
    default_passwords[lower_val]
}

is_hardcoded_password(val_str) {
    count(val_str) > 0
    not regex.match("^\\s*$", val_str)
    not is_external_reference(val_str)
    not is_variable_reference(val_str)
}

looks_like_password(str_val) {
    is_hardcoded_password(str_val)
}

looks_like_password(str_val) {
    is_default_password(str_val)
}

hash_value_key_str(entry) = key_str {
    entry.key.ir_type == "String"
    key_str := entry.key.value
}

hash_value_key_str(entry) = key_str {
    not entry.key.ir_type == "String"
    key_str := ""
}

# Walk all nodes using native walk and collect credential pairs with paths
# Returns objects with key, val_node, and full path from root
walk_and_collect(root, root_path) = findings {
    findings := {f |
        some [path, node] in walk(root)
        node.ir_type == "Hash"
        some entry in node.value
        key_str := hash_value_key_str(entry)
        key_str != ""
        is_credential_attribute(key_str)
        val_node := entry.value
        f := {
            "key": key_str,
            "val_node": val_node,
            "base_path": root_path
        }
    }
}

# Check a credential finding and emit result if it's a hardcoded password
emit_credential_finding(finding) = result {
    finding.val_node.ir_type == "String"
    val_str := finding.val_node.value
    looks_like_password(val_str)
    result := {
        "type": "sec_hard_pass",
        "element": finding.val_node,
        "path": finding.base_path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration. Use secret management services instead. (CWE-259)"
    }
}

# Direct credential check for Variable with String value
check_variable_direct(var, path) = result {
    var.ir_type == "Variable"
    is_credential_attribute(var.name)
    var.value.ir_type == "String"
    val_str := var.value.value
    looks_like_password(val_str)
    result := {
        "type": "sec_hard_pass",
        "element": var.value,
        "path": path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration. Use secret management services instead. (CWE-259)"
    }
}

# Direct credential check for Attribute with String value
check_attribute_direct(attr, path) = result {
    attr.ir_type == "Attribute"
    is_credential_attribute(attr.name)
    attr.value.ir_type == "String"
    val_str := attr.value.value
    looks_like_password(val_str)
    result := {
        "type": "sec_hard_pass",
        "element": attr.value,
        "path": path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration. Use secret management services instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in glitch_lib.all_variables(parent)
    result := check_variable_direct(var, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in glitch_lib.all_variables(parent)
    var.value.ir_type in {"Hash", "Array"}
    all_findings := walk_and_collect(var.value, parent.path)
    some finding in all_findings
    result := emit_credential_finding(finding)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr in glitch_lib.all_attributes(parent)
    result := check_attribute_direct(attr, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr in glitch_lib.all_attributes(parent)
    attr.value.ir_type in {"Hash", "Array"}
    all_findings := walk_and_collect(attr.value, parent.path)
    some finding in all_findings
    result := emit_credential_finding(finding)
}