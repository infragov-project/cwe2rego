package glitch

import data.glitch_lib

suspicious_pattern := `(?i)(password|secret|passphrase|credential|api_key|token|auth_key|admin_password|db_password|shared_secret|initial_password|bootstrap_credentials|key)`

check_hardcoded_password(value) {
    value.ir_type == "Hash"
    kv := value.value[_]
    kv.key.ir_type == "String"
    regex.match(suspicious_pattern, kv.key.value)
    kv.value.ir_type == "String"
}

check_hardcoded_password(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    check_hardcoded_password(elem)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    regex.match(suspicious_pattern, variable.name)
    variable.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding credentials directly into code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    variable.value.ir_type == "Hash"
    check_hardcoded_password(variable.value)
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding credentials directly into code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    variable.value.ir_type == "Array"
    check_hardcoded_password(variable.value)
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding credentials directly into code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    regex.match(suspicious_pattern, attr.name)
    attr.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding credentials directly into code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "Hash"
    check_hardcoded_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding credentials directly into code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "Array"
    check_hardcoded_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding credentials directly into code. (CWE-259)"
    }
}