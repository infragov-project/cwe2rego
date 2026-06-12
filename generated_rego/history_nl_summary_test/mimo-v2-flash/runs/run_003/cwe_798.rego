package glitch

import data.glitch_lib

credential_fields := {
    "password", "secret", "key", "token", "credential", "auth", "passphrase",
    "secret_key", "access_key", "api_key", "client_secret", "admin_password", "root_password",
    "db_password", "connection_string", "private_key", "service_account_token",
    "sha512_password", "keystore_password", "truststore_password", "secret_uuid", "service_key", "auth_token",
    "keystore", "truststore", "rbd_secret_uuid", "user", "username"
}

is_credential_field(name) {
    field := credential_fields[_]
    regex.match(sprintf("(?i)\\b%s\\b", [field]), name)
}

is_hardcoded_credential(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("^\\$\\{.*\\}$", value.value)
    not regex.match("^var\\.", value.value)
    not regex.match("^secret\\.", value.value)
    not regex.match("^vault\\.", value.value)
    not regex.match("^::", value.value)
}

find_hardcoded_credentials(node) = credentials {
    attrs := {c |
        walk(node, [path, n])
        n.ir_type == "Attribute"
        is_credential_field(n.name)
        is_hardcoded_credential(n.value)
        c := n
    }
    vars := {c |
        walk(node, [path, n])
        n.ir_type == "Variable"
        is_credential_field(n.name)
        is_hardcoded_credential(n.value)
        c := n
    }
    hashes := {c |
        walk(node, [path, n])
        n.ir_type == "Hash"
        pair := n.value[_]
        pair.key.ir_type == "String"
        is_credential_field(pair.key.value)
        is_hardcoded_credential(pair.value)
        c := pair.value
    }
    credentials := attrs | vars | hashes
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    credentials := find_hardcoded_credentials(parent)
    count(credentials) > 0
    credential := credentials[_]
    
    result := {
        "type": "sec_hard_secr",
        "element": credential,
        "path": parent.path,
        "description": "Use of hard-coded credential in IaC script - Avoid hard-coding credentials in scripts. (CWE-798)"
    }
}