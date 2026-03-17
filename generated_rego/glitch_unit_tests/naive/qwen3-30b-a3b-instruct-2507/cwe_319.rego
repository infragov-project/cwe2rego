package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == data.security.storage_resources[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "enableHttpsTrafficOnly" or attr.name == "secure_transfer_enabled" or attr.name == "https_only" or attr.name == "require_secure_transport" or attr.name == "enforce_tls" or attr.name == "use_secure_transport"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information detected: encryption for data in transit is disabled or not enforced. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == data.security.network_resources[_] or node.type == data.security.api_resources[_] or node.type == data.security.database_resources[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "protocol" or attr.name == "endpoint_url" or attr.name == "database_endpoint"
    attr.value.ir_type == "String"
    contains(attr.value.value, "http://")
    not contains(attr.value.value, "https://")

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information detected: unencrypted HTTP protocol used in endpoint or communication. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == data.security.storage_resources[_] or node.type == data.security.database_resources[_] or node.type == data.security.network_resources[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "public_access" or attr.name == "allow_all" or attr.name == "access_from"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    not some flag in [ "enableHttpsTrafficOnly", "secure_transfer_enabled", "require_secure_transport", "enforce_tls", "use_secure_transport" ] {
        some attr2 in attrs {
            attr2.name == flag
            attr2.value.ir_type == "Boolean"
            attr2.value.value == true
        }
    }

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information detected: publicly accessible resource with no encryption enforcement. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == data.security.iot_resources[_] or node.type == data.security.hardware_resources[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "jtag_access" or attr.name == "debug_interface" or attr.name == "hardware_debug_port"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    not some attr2 in attrs { 
        attr2.name == "use_unencrypted_channel" and attr2.value.ir_type == "Boolean" and attr2.value.value == false 
    }
    not some attr2 in attrs { 
        attr2.name == "secure_transport" and attr2.value.ir_type == "Boolean" and attr2.value.value == true 
    }

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information detected: unsecured debug or hardware interface exposed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == data.security.secrets_resources[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    (contains(attr.value.value, "password") or contains(attr.value.value, "token") or contains(attr.value.value, "secret") or contains(attr.value.value, "key"))
    not contains(attr.value.value, "encrypted")
    not contains(attr.value.value, "vault")
    not contains(attr.value.value, "kms")

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information detected: plaintext secret stored in infrastructure definition. (CWE-319)"
    }
}