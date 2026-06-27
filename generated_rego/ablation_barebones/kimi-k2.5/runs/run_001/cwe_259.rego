package glitch

import data.glitch_lib

password_patterns := ["password", "passwd", "pwd", "pass", "secret", "credential", "auth"]

check_hardcoded_password(attr) {
    attr.value.ir_type == "String"
    attr.value.value != ""
    attr.value.value != "null"
    attr.value.value != "undefined"
    attr.value.value != "None"
    attr.value.value != "nil"
    attr.value.value != "${"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    contains(lower_name, password_patterns[_])
    check_hardcoded_password(attr)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    lower_name := lower(var.name)
    contains(lower_name, password_patterns[_])
    check_hardcoded_password(var)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    hash_pair := attr.value.value[_]
    lower_key := lower(hash_pair[0].value)
    contains(lower_key, password_patterns[_])
    hash_pair[1].ir_type == "String"
    hash_pair[1].value != ""
    hash_pair[1].value != "null"
    hash_pair[1].value != "undefined"
    hash_pair[1].value != "None"
    hash_pair[1].value != "nil"
    hash_pair[1].value != "${"
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}