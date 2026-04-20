package glitch

import data.glitch_lib
import future.keywords.in

insecure_protocols = {"http://", "ftp://", "telnet://", "smtp://"}

insecure_encryption_flags = {"ssl", "ssl_mode", "use_ssl", "start_tls", "ssl_skip_verify", "validate_certs", "tls", "https", "enforce_https", "require_ssl", "force_tls", "https_only", "secure_transport", "enable_https"}

insecure_service_patterns = {
    {"name": "protocol", "value": "http"},
    {"name": "listener_protocol", "value": "HTTP"},
    {"name": "ssl_mode", "value": "disabled"},
    {"name": "allow_http_traffic", "value": "true"},
    {"name": "allow_blob_public_access", "value": "true"},
    {"name": "security_policy", "value": "plaintext"}
}

debug_keywords = {"debug", "test", "dev", "staging"}

contains_insecure_protocol(value) {
    value.ir_type == "String"
    some protocol in insecure_protocols
    contains(value.value, protocol)
}

contains_insecure_protocol(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    some protocol in insecure_protocols
    contains(node.value, protocol)
}

is_insecure_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_insecure_value(value) {
    value.ir_type == "String"
    lower(value.value) in {"false", "disabled", "no"}
}

is_debug_attribute(name) {
    some keyword in debug_keywords
    contains(lower(name), keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    contains_insecure_protocol(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Unencrypted protocol used in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains_insecure_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted protocol used in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    flag := insecure_encryption_flags[_]
    contains(lower(var.name), lower(flag))
    is_insecure_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Encryption enforcement disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    flag := insecure_encryption_flags[_]
    contains(lower(attr.name), lower(flag))
    is_insecure_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption enforcement disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    pattern := insecure_service_patterns[_]
    contains(lower(var.name), lower(pattern.name))
    var.value.ir_type == "String"
    lower(var.value.value) == pattern.value
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Insecure service configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    pattern := insecure_service_patterns[_]
    contains(lower(attr.name), lower(pattern.name))
    attr.value.ir_type == "String"
    lower(attr.value.value) == pattern.value
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure service configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    is_debug_attribute(var.name)
    contains_insecure_protocol(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Debug or test interface set to insecure endpoint. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_debug_attribute(attr.name)
    contains_insecure_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Debug or test interface set to insecure endpoint. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    is_debug_attribute(var.name)
    is_insecure_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Debug or test interface exposed without security. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_debug_attribute(attr.name)
    is_insecure_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Debug or test interface exposed without security. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[_].key.ir_type == "String"
    node.value[_].value.ir_type == "String"
    key := node.value[_].key.value
    value := node.value[_].value.value
    some pattern in insecure_service_patterns
    contains(lower(key), lower(pattern.name))
    lower(value) == pattern.value
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Insecure service configuration in Hash. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[_].key.ir_type == "String"
    node.value[_].value.ir_type == "String"
    key := node.value[_].key.value
    value := node.value[_].value.value
    some flag in insecure_encryption_flags
    contains(lower(key), lower(flag))
    lower(value) in {"false", "disabled", "no"}
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Encryption enforcement disabled in Hash. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    node.value[_].key.ir_type == "String"
    node.value[_].value.ir_type == "String"
    value := node.value[_].value.value
    some protocol in insecure_protocols
    contains(value, protocol)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Unencrypted protocol in Hash value. (CWE-319)"
    }
}