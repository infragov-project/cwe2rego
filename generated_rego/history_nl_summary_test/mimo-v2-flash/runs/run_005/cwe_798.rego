package glitch

import data.glitch_lib

credential_pattern := "(?i)\\b(password|secret|token|credential|auth|passwd|pwd|private_key|secret_key|api_key|access_key|keystore|truststore|store_password|user_password|admin_password|db_password)\\b"
dummy_pattern := "(?i)(changeme|example|dummy|test|placeholder)"
file_path_pattern := "(?i)(^/|^[a-z]:|\\.[a-z]{2,5}$)"

check_value(value) {
    value.ir_type == "String"
    not regex.match(dummy_pattern, value.value)
    not regex.match(file_path_pattern, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    regex.match(credential_pattern, var.name)
    check_value(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(credential_pattern, attr.name)
    check_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    kv := n.value[_]
    key := kv.key
    key.ir_type == "String"
    regex.match(credential_pattern, key.value)
    value := kv.value
    value.ir_type == "String"
    check_value(value)
    result := {
        "type": "sec_hard_secr",
        "element": key,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}