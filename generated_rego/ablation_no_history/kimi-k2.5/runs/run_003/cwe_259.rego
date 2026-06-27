package glitch

import data.glitch_lib

password_field_patterns := {"password", "secret", "pwd", "pass", "token", "key", "credentials", "auth"}

is_password_related(key_name) {
    lower_key := lower(key_name)
    pw_pattern := password_field_patterns[_]
    contains(lower_key, pw_pattern)
}

is_trivial_password(s) {
    lower(s) == ""
}

is_trivial_password(s) {
    lower(s) == "password"
}

is_trivial_password(s) {
    lower(s) == "admin"
}

is_trivial_password(s) {
    lower(s) == "123456"
}

is_trivial_password(s) {
    lower(s) == "default"
}

looks_like_secret_ref(s) {
    regex.match("^\\s*\\{", s)
}

looks_like_secret_ref(s) {
    regex.match("^\\$\\{", s)
}

looks_like_secret_ref(s) {
    regex.match("^\\%\\{", s)
}

looks_like_secret_ref(s) {
    regex.match("^\\s*vault\\s*\\{", lower(s))
}

looks_like_secret_ref(s) {
    regex.match("^\\s*data\\s*\\.", lower(s))
}

looks_like_secret_ref(s) {
    regex.match("^\\s*var\\s*\\.", lower(s))
}

looks_like_secret_ref(s) {
    regex.match("^\\s*local\\s*\\.", lower(s))
}

looks_like_secret_ref(s) {
    regex.match("^\\s*lookup\\s*\\(", lower(s))
}

looks_like_secret_ref(s) {
    regex.match("^\\s*secrets?\\s*\\(", lower(s))
}

is_hardcoded_string(val) {
    val.ir_type == "String"
    val.value != ""
    not is_trivial_password(val.value)
    not looks_like_secret_ref(val.value)
}

walk_value_for_passwords(val, parent_path, results) {
    val.ir_type == "String"
    is_hardcoded_string(val)
    results := {{"type": "sec_hard_pass", "element": val, "path": parent_path, "description": "Use of hard-coded password - Avoid hard-coding credentials in configuration files. Use secret management solutions or environment variables. (CWE-259)"}}
}

walk_value_for_passwords(val, parent_path, results) {
    val.ir_type != "String"
    val.ir_type != "Hash"
    val.ir_type != "Array"
    results := set()
}

walk_value_for_passwords(val, parent_path, results) {
    val.ir_type == "Hash"
    sub_results := {r | some k; subval := val.value[k]; is_password_related(k); walk_value_for_passwords(subval, parent_path, subres); r := subres[_]}
    results := sub_results
}

walk_value_for_passwords(val, parent_path, results) {
    val.ir_type == "Hash"
    sub_results := {r | some k; subval := val.value[k]; not is_password_related(k); subval.ir_type == "Hash"; walk_value_for_passwords(subval, parent_path, subres); r := subres[_]}
    sub_results2 := {r | some k; subval := val.value[k]; not is_password_related(k); subval.ir_type == "Array"; walk_value_for_passwords(subval, parent_path, subres); r := subres[_]}
    results := sub_results | sub_results2
}

walk_value_for_passwords(val, parent_path, results) {
    val.ir_type == "Array"
    sub_results := {r | some i; subval := val.value[i]; walk_value_for_passwords(subval, parent_path, subres); r := subres[_]}
    results := sub_results
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_related(var.name)
    var.value.ir_type == "String"
    is_hardcoded_string(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coding credentials in configuration files. Use secret management solutions or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_related(var.name)
    walk_value_for_passwords(var.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    not is_password_related(var.name)
    var.value.ir_type == "Hash"
    walk_value_for_passwords(var.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    not is_password_related(var.name)
    var.value.ir_type == "Array"
    walk_value_for_passwords(var.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    au_attrs := glitch_lib.all_attributes(au)
    attr := au_attrs[_]
    is_password_related(attr.name)
    attr.value.ir_type == "String"
    is_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coding credentials in configuration files. Use secret management solutions or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    au_attrs := glitch_lib.all_attributes(au)
    attr := au_attrs[_]
    is_password_related(attr.name)
    walk_value_for_passwords(attr.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    au_attrs := glitch_lib.all_attributes(au)
    attr := au_attrs[_]
    not is_password_related(attr.name)
    attr.value.ir_type == "Hash"
    walk_value_for_passwords(attr.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    au_attrs := glitch_lib.all_attributes(au)
    attr := au_attrs[_]
    not is_password_related(attr.name)
    attr.value.ir_type == "Array"
    walk_value_for_passwords(attr.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_related(attr.name)
    attr.value.ir_type == "String"
    is_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coding credentials in configuration files. Use secret management solutions or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_related(attr.name)
    walk_value_for_passwords(attr.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    not is_password_related(attr.name)
    attr.value.ir_type == "Hash"
    walk_value_for_passwords(attr.value, parent.path, results)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    not is_password_related(attr.name)
    attr.value.ir_type == "Array"
    walk_value_for_passwords(attr.value, parent.path, results)
    result := results[_]
}