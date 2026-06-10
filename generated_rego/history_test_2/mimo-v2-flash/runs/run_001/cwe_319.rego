package glitch

import data.glitch_lib

encryption_disable_attributes = {
    "enable_https_only",
    "secure_transfer_enabled",
    "encryption_protocol",
    "allow_blob_public_access",
    "ssl_enforcement",
    "require_ssl",
    "database_encryption",
    "public_network_access",
    "protocol",
    "ssl_certificate",
    "redirect_http_to_https",
    "kafka_encrypted",
    "use_ssl",
    "encryption",
    "allow_unencrypted_ingress"
}

insecure_protocols = {"http", "ftp", "smtp"}

insecure_protocol_patterns = {"http://", "ftp://", "smtp://"}

environment_attributes = {"environment", "env", "environment_variables"}

user_data_attributes = {"user_data", "user_data_script"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    encryption_disable_attributes[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    encryption_disable_attributes[attr.name]
    attr.value.ir_type == "String"
    attr.value.value == "false"

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "protocol"
    attr.value.ir_type == "String"
    insecure_protocols[attr.value.value]

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    environment_attributes[attr.name]
    attr.value.ir_type == "Hash"

    pattern := insecure_protocol_patterns[_]
    glitch_lib.traverse(attr.value, pattern)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Environment variables use insecure protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    user_data_attributes[attr.name]
    attr.value.ir_type == "String"

    pattern := insecure_protocol_patterns[_]
    glitch_lib.traverse(attr.value, pattern)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - User data uses insecure protocol. (CWE-319)"
    }
}