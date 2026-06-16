package glitch

import data.glitch_lib

binding_attributes_pattern := "(?i).*bind.*|.*listen.*|.*ip.*|.*address.*|.*addr.*"
exposure_attributes_pattern := "^(publicly_accessible|allow_all_ips|ingress_cidr|network_access)$"
cidr_pattern := "^0\\.0\\.0\\.0/0$"

check_binding_value(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
}

check_binding_value(value) {
    value.ir_type == "VariableReference"
    value.value == "0.0.0.0"
}

check_exposure_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

check_exposure_value(value) {
    value.ir_type == "String"
    regex.match(cidr_pattern, value.value)
}

get_key_string(key) = str {
    key.ir_type == "String"
    str := key.value
}

get_key_string(key) = str {
    key.ir_type == "VariableReference"
    str := key.value
}

get_key_string(key) = str {
    str := ""
}

check_value(value, check_type) {
    check_type == "binding"
    check_binding_value(value)
}

check_value(value, check_type) {
    check_type == "exposure"
    check_exposure_value(value)
}

check_hash_entries(node, key_pattern, check_type) {
    node.ir_type == "Hash"
    entry := node.value[_]
    key_str := get_key_string(entry.key)
    regex.match(key_pattern, key_str)
    check_value(entry.value, check_type)
}

check_hash_entries(node, key_pattern, check_type) {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.value.ir_type == "Hash"
    check_hash_entries(entry.value, key_pattern, check_type)
}

check_hash_entries(node, key_pattern, check_type) {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.value.ir_type == "Array"
    check_array_elements(entry.value, key_pattern, check_type)
}

check_array_elements(node, key_pattern, check_type) {
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Hash"
    check_hash_entries(elem, key_pattern, check_type)
}

check_array_elements(node, key_pattern, check_type) {
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Array"
    check_array_elements(elem, key_pattern, check_type)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(binding_attributes_pattern, attr.name)
    check_binding_value(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to all network interfaces (0.0.0.0) without restrictions. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(exposure_attributes_pattern, attr.name)
    check_exposure_value(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network exposure allowing traffic from any IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(binding_attributes_pattern, var.name)
    check_value(var.value, "binding")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to all network interfaces (0.0.0.0) without restrictions. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(exposure_attributes_pattern, var.name)
    check_value(var.value, "exposure")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network exposure allowing traffic from any IP. (CWE-1327)"
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
    check_hash_entries(attr.value, binding_attributes_pattern, "binding")
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to all network interfaces (0.0.0.0) without restrictions in nested configuration. (CWE-1327)"
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
    check_hash_entries(attr.value, exposure_attributes_pattern, "exposure")
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network exposure allowing traffic from any IP in nested configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    check_hash_entries(var.value, binding_attributes_pattern, "binding")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to all network interfaces (0.0.0.0) without restrictions in nested configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    check_hash_entries(var.value, exposure_attributes_pattern, "exposure")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network exposure allowing traffic from any IP in nested configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    check_array_elements(attr.value, binding_attributes_pattern, "binding")
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to all network interfaces (0.0.0.0) without restrictions in array configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    check_array_elements(attr.value, exposure_attributes_pattern, "exposure")
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network exposure allowing traffic from any IP in array configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    check_array_elements(var.value, binding_attributes_pattern, "binding")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to all network interfaces (0.0.0.0) without restrictions in array configuration. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    check_array_elements(var.value, exposure_attributes_pattern, "exposure")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network exposure allowing traffic from any IP in array configuration. (CWE-1327)"
    }
}