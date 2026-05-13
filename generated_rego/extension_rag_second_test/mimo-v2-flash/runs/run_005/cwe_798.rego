package glitch

import data.glitch_lib

keyword_pattern = `(?i)\b(password|passwd|pwd|secret|token|key|credential|auth|user|username|access_key|secret_key|api_key|bearer_token|client_secret)\b`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.ir_type == "Variable"
    var_name := v.name
    regex.match(keyword_pattern, var_name)
    v.value.ir_type == "String"
    string_value := v.value.value
    string_value != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in variable '%s' - Avoid using hard-coded credentials. (CWE-798)", [var_name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    a.ir_type == "Attribute"
    attr_name := a.name
    regex.match(keyword_pattern, attr_name)
    a.value.ir_type == "String"
    string_value := a.value.value
    string_value != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": a,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in attribute '%s' - Avoid using hard-coded credentials. (CWE-798)", [attr_name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_expr := pair.key
    value_expr := pair.value
    key_expr.ir_type == "String"
    key_str := key_expr.value
    regex.match(keyword_pattern, key_str)
    value_expr.ir_type == "String"
    value_str := value_expr.value
    value_str != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": value_expr,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in key '%s' - Avoid using hard-coded credentials. (CWE-798)", [key_str])
    }
}