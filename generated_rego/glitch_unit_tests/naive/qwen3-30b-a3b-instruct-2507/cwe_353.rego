package glitch

import data.glitch_lib

integrity_fields := {"checksum", "hash", "signature", "integrity", "digest", "mac", "auth_tag", "content-md5", "x-amz-content-sha256"}

transport_insecure := {"udp", "http", "unreliable", "none"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    integrity_field := integrity_fields[_]
    attr.name == integrity_field

    not result := { }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    attr.value.value == transport_insecure[_]

    any_attr_with_missing_integrity := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check in data-in-transit: Protocol or configuration lacks integrity validation mechanisms such as checksums, MACs, or cryptographic hashes. (CWE-353)"
    }

    result := any_attr_with_missing_integrity
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "aws_lambda_event_source_mapping"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "verify_signature"
    not attr.value == true

    # Replace invalid `not some ... where` with correct condition using `not` and `exists`
    not exists {
        attr2 := attrs[_]
        attr2.name == "source_arn_filtering"
    }

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing message integrity verification in event triggers: Event source mapping lacks signature verification or source filtering, increasing risk of tampering. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "aws_s3_event_notification"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "verify_signature"
    not attr.value == true

    not exists {
        attr2 := attrs[_]
        attr2.name == "source_arn_filtering"
    }

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing message integrity verification in event triggers: Event source mapping lacks signature verification or source filtering, increasing risk of tampering. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "aws_sqs_queue"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "encryption_enabled"
    not attr.value == true

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "SQS queue configured without encryption or integrity checks – data in transit may be altered undetected. (CWE-353)"
    }
}