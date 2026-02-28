package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all atomic units in parent
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for weak encryption configurations
    weak_encryption_check(attr)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak encryption algorithm, key length, or protocol version. (CWE-326)"
    }
}

# Check for variables with weak cryptographic values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable value uses weak cryptography
    weak_variable_value(var)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak encryption algorithm, key length, or protocol version. (CWE-326)"
    }
}

# Detect weak cryptographic algorithms in values
weak_encryption_check(attr) {
    # Check if value contains weak cryptographic patterns
    attr.value.ir_type == "String"
    regex.match("(?i)(md5|sha1|des|3des|rc4|blowfish|aes128|tls[-_ ]?1\\.0|tls[-_ ]?1\\.1|ssl[-_ ]?3\\.0)", attr.value.value)
}

# Detect FunctionCall with weak hashing algorithms
weak_encryption_check(attr) {
    attr.value.ir_type == "FunctionCall"
    weak_function_check(attr.value)
}

# Detect MethodCall with weak hashing algorithms  
weak_encryption_check(attr) {
    attr.value.ir_type == "MethodCall"
    weak_method_check(attr.value)
}

# Detect Sum expressions with weak hashing
weak_encryption_check(attr) {
    attr.value.ir_type == "Sum"
    weak_sum_check(attr.value)
}

# Helper functions for different IaC patterns
weak_function_check(func) {
    func.name == "postgresql_password"
}

weak_function_check(func) {
    func.name == "hash"
    count(func.args) > 0
    func.args[1].ir_type == "String"
    regex.match("(?i)(md5|sha1)", func.args[1].value)
}

weak_method_check(method) {
    method.method == "hexdigest"
    method.receiver.ir_type == "VariableReference"
    regex.match("(?i)md5|sha1", method.receiver.value)
}

weak_method_check(method) {
    method.method == "hexdigest"
    method.receiver.ir_type == "VariableReference"
    method.receiver.value == "Digest::MD5"
}

weak_sum_check(sum_expr) {
    # Check if sum contains weak hashing references
    walk(sum_expr, [_, node])
    node.ir_type == "VariableReference"
    regex.match("(?i)md5|sha1", node.value)
}

# Detect weak patterns in shell commands
weak_encryption_check(attr) {
    attr.name == "shell"
    attr.value.ir_type == "Sum"
    walk(attr.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)md5", node.value)
}

# Check for variables with weak cryptographic values
weak_variable_value(var) {
    var.value.ir_type == "MethodCall"
    weak_method_check(var.value)
}

weak_variable_value(var) {
    var.value.ir_type == "FunctionCall"
    weak_function_check(var.value)
}

weak_variable_value(var) {
    var.value.ir_type == "String"
    regex.match("(?i)(md5|sha1)", var.value.value)
}

# Detect weak patterns in Sum expressions for variables
weak_variable_value(var) {
    var.value.ir_type == "Sum"
    walk(var.value, [_, node])
    node.ir_type == "FunctionCall"
    weak_function_check(node)
}

weak_variable_value(var) {
    var.value.ir_type == "Sum"
    walk(var.value, [_, node])
    node.ir_type == "MethodCall"
    weak_method_check(node)
}

weak_variable_value(var) {
    var.value.ir_type == "Sum"
    walk(var.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)(md5|sha1)", node.value)
}

# Detect weak patterns in Hash values (Ansible set_fact)
weak_encryption_check(attr) {
    attr.value.ir_type == "Hash"
    walk(attr.value, [_, node])
    node.ir_type == "FunctionCall"
    weak_function_check(node)
}

weak_encryption_check(attr) {
    attr.value.ir_type == "Hash"
    walk(attr.value, [_, node])
    node.ir_type == "MethodCall"
    weak_method_check(node)
}

weak_encryption_check(attr) {
    attr.value.ir_type == "Hash"
    walk(attr.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)(md5|sha1)", node.value)
}

# Detect weak patterns in Sum expressions (Ansible)
weak_encryption_check(attr) {
    attr.value.ir_type == "Sum"
    walk(attr.value, [_, node])
    node.ir_type == "FunctionCall"
    weak_function_check(node)
}

weak_encryption_check(attr) {
    attr.value.ir_type == "Sum"
    walk(attr.value, [_, node])
    node.ir_type == "MethodCall"
    weak_method_check(node)
}

weak_encryption_check(attr) {
    attr.value.ir_type == "Sum"
    walk(attr.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)(md5|sha1)", node.value)
}