package glitch

import data.glitch_lib

is_wildcard_val(value) {
    value.ir_type == "String"
    value.value == "*"
}

is_wildcard_val(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == "*"
}

is_open_ip(value) {
    value.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0(/0)?|::/0)$", value.value)
}

is_open_ip(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0(/0)?|::/0)$", item.value)
}

is_false_val(value) {
    value.ir_type == "Boolean"
    value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(actions?|resources?|principals?|not_action|not_principal|not_resource)$", attr.name)
    is_wildcard_val(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy - Wildcard in action/resource/principal. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(publicly_accessible|public_access|public_network_access_enabled|blob_public_access|allow_blob_public_access)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible resource - Exposed to the public internet. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)$", attr.name)
    is_false_val(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access block disabled - Resource does not restrict public access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_open_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Overly broad network binding - Service binds to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_open_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly broad network binding - Service binds to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    is_open_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Overly broad network binding - Hash entry binds to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(authentication_enabled|auth_enabled|require_auth|enable_auth|client_cert_enabled)$", attr.name)
    is_false_val(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Resource has authentication explicitly disabled. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(anonymous_access|anonymous_authentication|no_auth)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Anonymous access enabled - Resource allows unauthenticated access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(authorization_type|auth_type)$", attr.name)
    attr.value.ir_type == "String"
    upper(attr.value.value) == "NONE"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Missing API authorization - Endpoint authorization type is NONE. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(logging_enabled|audit_log_enabled|enable_logging|cloudtrail_enabled|flow_logs_enabled)$", attr.name)
    is_false_val(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Access logging or auditing disabled - Sensitive resource lacks audit trail. (CWE-284)"
    }
}