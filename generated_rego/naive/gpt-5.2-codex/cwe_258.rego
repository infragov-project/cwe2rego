package glitch

import data.glitch_lib

password_name_pattern := "(?i).*(password|passwd|pwd|passphrase|secret|credential).*"
empty_password_flag_pattern := "(?i).*(allow[_-]?empty[_-]?password|permit[_-]?empty[_-]?password|empty[_-]?password[_-]?allowed|no[_-]?password|skip[_-]?password[_-]?auth|disable[_-]?password).*"
empty_password_segment_pattern := "(?i)(password|pwd|pass)\\s*=\\s*($|[;&])"
empty_password_description := "Empty password in configuration file - Password fields should not be empty or allow empty passwords. (CWE-258)"

is_empty_password_flag(name) {
    regex.match(empty_password_flag_pattern, name)
}

is_password_name(name) {
    regex.match(password_name_pattern, name)
    not is_empty_password_flag(name)
}

is_empty_value(v) {
    v.ir_type == "String"
    regex.match("^\\s*$", v.value)
}
is_empty_value(v) { v.ir_type == "Null" }
is_empty_value(v) { v.ir_type == "Undef" }

is_true_value(v) { v.ir_type == "Boolean"; v.value == true }
is_true_value(v) { v.ir_type == "String"; regex.match("(?i)^\\s*(true|yes|1|on)\\s*$", v.value) }
is_true_value(v) { v.ir_type == "Integer"; v.value == 1 }

var_or_attr_empty(parent, name) {
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    lower(v.name) == lower(name)
    is_empty_value(v.value)
}
var_or_attr_empty(parent, name) {
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    lower(a.name) == lower(name)
    is_empty_value(a.value)
}

empty_or_ref_empty(parent, v) { is_empty_value(v) }
empty_or_ref_empty(parent, v) { v.ir_type == "VariableReference"; var_or_attr_empty(parent, v.value) }

key_is_password(k) { k.ir_type == "String"; is_password_name(k.value) }
key_is_password(k) { k.ir_type == "VariableReference"; is_password_name(k.value) }

key_is_empty_password_flag(k) { k.ir_type == "String"; is_empty_password_flag(k.value) }
key_is_empty_password_flag(k) { k.ir_type == "VariableReference"; is_empty_password_flag(k.value) }

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    empty_or_ref_empty(parent, attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": empty_password_description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_name(v.name)
    empty_or_ref_empty(parent, v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": empty_password_description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_empty_password_flag(attr.name)
    is_true_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": empty_password_description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_empty_password_flag(v.name)
    is_true_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": empty_password_description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    key := entry.key
    val := entry.value
    key_is_password(key)
    empty_or_ref_empty(parent, val)
    result := {
        "type": "sec_empty_pass",
        "element": key,
        "path": parent.path,
        "description": empty_password_description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    key := entry.key
    val := entry.value
    key_is_empty_password_flag(key)
    is_true_value(val)
    result := {
        "type": "sec_empty_pass",
        "element": key,
        "path": parent.path,
        "description": empty_password_description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    regex.match(empty_password_segment_pattern, s.value)
    result := {
        "type": "sec_empty_pass",
        "element": s,
        "path": parent.path,
        "description": empty_password_description
    }
}