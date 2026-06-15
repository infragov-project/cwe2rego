package glitch

import data.glitch_lib

protocol_keys := {"protocol", "load_balancer_protocol", "api_gateway_protocol", "transfer_protocol", "endpoint_type", "listener_protocol"}

insecure_protocols := {"http", "tcp", "ftp"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in protocol_keys
    attr.value.ir_type == "String"
    protocol_value := attr.value.value
    protocol_value in insecure_protocols

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Using insecure protocol without integrity validation (CWE-353)"
    }
}

encryption_keys := {"encryption", "secure_transfer", "use_ssl", "tls_version", "ssl_policy", "ssl_mode"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in encryption_keys
    (
        (attr.value.ir_type == "Boolean" and attr.value.value == false) or
        (attr.value.ir_type == "String" and (attr.value.value == "disabled" or attr.value.value == "none"))
    )

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Encryption or TLS disabled (CWE-353)"
    }
}

validation_keys := {"checksum_validation", "disable_checksum", "enable_data_validation", "signature_algorithm", "auth_mechanism", "content_validation", "security_policy", "compliance_mode"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in validation_keys
    (
        (attr.value.ir_type == "Boolean" and attr.value.value == false) or
        (attr.value.ir_type == "String" and (attr.value.value == "none" or attr.value.value == "disabled" or attr.value.value == "default" or attr.value.value == "basic")) or
        (attr.value.ir_type == "Null")
    )

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity validation features omitted or disabled (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in validation_keys
    attr.value.ir_type == "String"
    attr.value.value == "basic"

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Basic auth without HMAC/digest support (CWE-353)"
    }
}