package glitch

import data.glitch_lib

weak_algorithm_pattern = `(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|md5_crypt|sha1|md5)`
weak_key_length_pattern = `(?i)(1024|56|64|160|192)`
weak_protocol_pattern = `(?i)(SSLv2|SSLv3|TLSv1|TLSv1_1)`

check_weak_value(value) {
    value.ir_type == "String"
    regex.match(weak_algorithm_pattern, value.value)
} else {
    value.ir_type == "String"
    regex.match(weak_key_length_pattern, value.value)
} else {
    value.ir_type == "String"
    regex.match(weak_protocol_pattern, value.value)
} else {
    value.ir_type == "Integer"
    value.value == 1024
} else {
    value.ir_type == "Integer"
    value.value == 56
} else {
    value.ir_type == "Integer"
    value.value == 64
} else {
    value.ir_type == "Integer"
    value.value == 160
} else {
    value.ir_type == "Integer"
    value.value == 192
} else {
    value.ir_type == "FunctionCall"
    check_weak_function_call(value)
}

check_weak_function_call(func) {
    regex.match(weak_algorithm_pattern, func.name)
} else {
    func.ir_type == "FunctionCall"
    arg := func.args[_]
    check_weak_value(arg)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := nodes[_]
    check_weak_value(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak encryption algorithm, key length, or protocol (CWE-326)"
    }
}