package glitch

import data.glitch_lib

binding_attributes := {"bind_address", "listen_address", "host", "ip_address", "server_address", "addr", "address", "listenaddr"}

check_hash_for_binding(value) {
    value.ir_type == "Hash"
    pair := value.value[_]
    key_expr := pair.key
    key_expr.ir_type == "String"
    key_expr.value == binding_attributes[_]
    pair.value.ir_type == "String"
    pair.value.value == "0.0.0.0"
}

check_hash_value(value) {
    value.ir_type == "Hash"
    check_hash_for_binding(value)
} else {
    value.ir_type == "Hash"
    pair := value.value[_]
    pair.value.ir_type == "Hash"
    check_hash_value(pair.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == binding_attributes[_]
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address (0.0.0.0) - Services should not bind to 0.0.0.0 as it allows connections from any IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    check_hash_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address (0.0.0.0) - Services should not bind to 0.0.0.0 as it allows connections from any IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    check_hash_value(var.value)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address (0.0.0.0) - Services should not bind to 0.0.0.0 as it allows connections from any IP. (CWE-1327)"
    }
}