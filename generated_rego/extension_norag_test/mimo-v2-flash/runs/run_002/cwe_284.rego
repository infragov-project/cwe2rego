package glitch

import data.glitch_lib

sensitive_patterns = {"bind", "ip", "address", "addr", "password", "public", "principal", "action", "resource", "cidr", "port", "protocol", "access", "acl", "owner", "permission", "encryption", "logging", "monitoring", "role", "sudo", "privileged", "authentication", "credentials", "publicly_accessible", "block_public_access", "bucket_policy", "storage_key_visibility", "inherit_permissions", "audit_trail", "enable_authentication", "use_default_credentials", "admin", "full-access", "replset", "journaling", "oplog", "replication", "security", "authorization", "bindip", "net", "auth", "replset", "journaling", "oplog", "replication"}

insecure_values = {"0.0.0.0", "public-read", "public-read-write", "0.0.0.0/0", "all", "disabled", "none", "nobody", "0777", "777", "admin", "passw0rd", "password", "testUser", "any", "open", "unrestricted", "allow-all", "world-readable", "unauthenticated", "anonymous", "hardcoded", "default"}

check_sensitive_name(name) {
    name.ir_type == "String"
    some pattern in sensitive_patterns
    contains_ci(name.value, pattern)
} else {
    name.ir_type == "VariableReference"
    some pattern in sensitive_patterns
    contains_ci(name.value, pattern)
}

check_insecure_value(value) {
    value.ir_type == "String"
    some insecure in insecure_values
    contains_ci(value.value, insecure)
} else {
    value.ir_type == "Integer"
    value.value == 777
}

check_hash_key_value_pair(key, value) {
    check_sensitive_name(key)
    check_insecure_value(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    check_sensitive_name(node.name)
    check_insecure_value(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Insecure access control configuration in variable"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    check_sensitive_name(node.name)
    check_insecure_value(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Insecure access control configuration in attribute"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some i
    pair := node.value[i]
    check_hash_key_value_pair(pair.key, pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": "Insecure access control configuration in hash"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    some i
    element := node.value[i]
    element.ir_type == "Hash"
    some j
    pair := element.value[j]
    check_hash_key_value_pair(pair.key, pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": "Insecure access control configuration in array element"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "MethodCall"
    check_sensitive_name(node.receiver)
    check_insecure_value(node.args[0])
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Insecure access control method call"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    node.left.ir_type == "VariableReference"
    check_sensitive_name(node.left)
    check_insecure_value(node.right)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Insecure access control in indexed access"
    }
}