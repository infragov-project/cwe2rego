package glitch

import data.glitch_lib

gpg_check_keys := {"gpgcheck", "repo_gpgcheck"}
disabled_true_keys := {"disable_gpg_check", "skip_checksum", "no_checksum", "checksum_disabled", "skip_tls_verify", "insecure", "gpg_autoimport_keys"}
tls_false_keys := {"verify_ssl", "tls_verify", "ssl_verify", "validate_certs"}
sig_false_keys := {"signature_check", "enforce_signing"}
integrity_names := {"checksum", "sha256", "sha512", "sha1", "md5", "hash", "digest", "integrity"}
download_types := {"get_url", "remote_file", "maven_artifact", "fetch", "archive"}
source_keys := {"url", "source", "src", "repo", "baseurl"}

is_falsy(v) { v.ir_type == "Integer"; v.value == 0 }
is_falsy(v) { v.ir_type == "Boolean"; v.value == false }
is_truthy(v) { v.ir_type == "Boolean"; v.value == true }

hash_kv_name(kv) = k { kv.key.ir_type == "String"; k := kv.key.value }

has_integrity_in_node(node) {
    walk(node, [_, kv])
    hash_kv_name(kv) == integrity_names[_]
}

has_integrity_in_node(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == integrity_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == gpg_check_keys[_]
    is_falsy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Package GPG check is disabled, allowing unverified packages to be installed. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    hash_kv_name(kv) == gpg_check_keys[_]
    is_falsy(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Package GPG check is disabled, allowing unverified packages to be installed. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == disabled_true_keys[_]
    is_truthy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity or checksum verification is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    hash_kv_name(kv) == disabled_true_keys[_]
    is_truthy(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity or checksum verification is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_false_keys[_]
    is_falsy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - TLS/SSL verification is disabled, removing transport-level integrity guarantees. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    hash_kv_name(kv) == tls_false_keys[_]
    is_falsy(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - TLS/SSL verification is disabled, removing transport-level integrity guarantees. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == sig_false_keys[_]
    is_falsy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Signature verification is disabled for a module or provider. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "image"
    attr.value.ir_type == "String"
    not regex.match("@sha256:", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Container image referenced without an immutable cryptographic digest (@sha256:). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == download_types[_]
    not has_integrity_in_node(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Download task lacks checksum or integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == source_keys[_]
    attr.value.ir_type == "String"
    startswith(attr.value.value, "http://")
    not has_integrity_in_node(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Artifact source uses insecure HTTP without integrity verification. (CWE-353)"
    }
}