package glitch

import data.glitch_lib

insecure_values := {"false", "disabled", "off", "none", "null", "no", "skip", "bypass", "0", "~", "no_check"}

integrity_keywords := {"verify", "verify_ssl", "verify_tls", "verify_peer", "verify_mode", "check", "gpgcheck", "validate", "validation", "valid", "checksum", "hash", "md5", "sha", "sha1", "sha256", "digest", "signature", "sig", "sign", "authentic", "integrity", "tls_verify", "ssl_verify", "peer_verify", "cert_verify", "ca_bundle", "gpg_key", "signed_by", "gpg_keys", "validate_certs", "strict", "verify_checksum", "skip_checksum", "trust_server_cert", "ssl", "tls"}

download_keywords := {"url", "source", "src", "uri", "download", "wget", "curl", "fetch", "get", "pull", "remote", "http", "https", "ftp", "archive", "package", "gem", "npm", "pip", "maven", "repo", "repository", "mirror", "baseurl", "location", "remote_file", "file"}

download_types := {"get_url", "uri", "remote_file", "archive", "download", "package", "gem_package", "npm_package", "yumrepo", "apt_repository", "zypper_repo"}

is_insecure_value(value) {
    value.ir_type == "String"
    lower(trim(value.value, "\" '\"'")) == insecure_values[_]
} else {
    value.ir_type == "String"
    regex.match("(?i)^(false|off|disabled|no|skip|bypass|none|null|0|~)$", value.value)
} else {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    value.ir_type == "Null"
}

is_insecure_integer_attr(name) {
    n := lower(name)
    contains(n, "gpgcheck")
} else {
    n := lower(name)
    contains(n, "verify")
}

is_external_url(value) {
    value.ir_type == "String"
    val := lower(trim(value.value, "\" \"'"))
    startswith(val, "http://")
} else {
    value.ir_type == "String"
    val := lower(trim(value.value, "\" \"'"))
    startswith(val, "https://")
} else {
    value.ir_type == "String"
    val := lower(trim(value.value, "\" \"'"))
    startswith(val, "ftp://")
}

contains_pattern(name, patterns) {
    n := lower(name)
    pattern := patterns[_]
    contains(n, pattern)
}

is_download_context(node) {
    node.ir_type == "AtomicUnit"
    contains_pattern(node.type, download_types)
} else {
    node.ir_type == "Attribute"
    contains_pattern(node.name, download_keywords)
}

gather_all_targets(node, acc) = result {
    walk(node, [path, n])
    n.ir_type == "KeyValue"
    name := lower(n.name)
    contains_pattern(n.name, integrity_keywords)
    result := {{"name": n.name, "value": n.value, "element": n, "path": path}}
}

extract_target_keys(node) = targets {
    targets := {t |
        walk(node, [path, n])
        n.ir_type == "KeyValue"
        contains_pattern(n.name, integrity_keywords)
        t := {"name": n.name, "value": n.value, "element": n}
    }
}

extract_nested_hashes(node) = pairs {
    pairs := {p |
        walk(node, [path, n])
        n.ir_type == "Hash"
        p := n
    }
}

extract_hash_pairs(hash) = pairs {
    walk(hash, [_, n])
    n.ir_type == "KeyValue"
    pairs := n
}

find_all_keyvalues(root) = kvs {
    kvs := {kv |
        walk(root, [_, n])
        n.ir_type == "KeyValue"
        kv := n
    }
}

find_all_in_hash(hash) = kvs {
    is_object(hash)
    hash.ir_type == "Hash"
    kvs := {kv |
        walk(hash, [_, n])
        n.ir_type == "KeyValue"
        kv := n
    }
} else = kvs {
    is_array(hash.value)
    kvs := {kv |
        some i
        item := hash.value[i]
        walk(item, [_, n])
        n.ir_type == "KeyValue"
        kv := n
    }
} else = kvs {
    kvs := set()
}

check_integer_insecure(kv) {
    is_insecure_integer_attr(kv.name)
    kv.value.ir_type == "Integer"
    kv.value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_kvs := find_all_keyvalues(parent)
    kv := all_kvs[_]
    
    contains_pattern(kv.name, integrity_keywords)
    is_insecure_value(kv.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_kvs := find_all_keyvalues(parent)
    kv := all_kvs[_]
    
    check_integer_insecure(kv)
    
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Missing support for integrity check - Integer-based integrity verification disabled (gpgcheck/verify=0). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    
    is_download_context(au)
    
    au_kvs := find_all_keyvalues(au)
    
    has_download_source(au_kvs)
    not has_integrity_protection(au_kvs)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Download operation without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_kvs := find_all_keyvalues(parent)
    
    some i, j
    src_kv := all_kvs[i]
    contains_pattern(src_kv.name, download_keywords)
    is_external_url(src_kv.value)
    
    not has_integrity_in_scope(all_kvs, src_kv)
    
    result := {
        "type": "sec_no_int_check",
        "element": src_kv,
        "path": parent.path,
        "description": "Missing support for integrity check - External URL without associated integrity verification. (CWE-353)"
    }
}

has_download_source(kvs) {
    kv := kvs[_]
    contains_pattern(kv.name, download_keywords)
    is_external_url(kv.value)
}

has_integrity_protection(kvs) {
    kv := kvs[_]
    contains_pattern(kv.name, integrity_keywords)
    not is_insecure_value(kv.value)
} else {
    kv := kvs[_]
    contains_pattern(kv.name, integrity_keywords)
    kv.value.ir_type == "Integer"
    kv.value.value != 0
} else {
    kv := kvs[_]
    kv.name == "checksum"
} else {
    kv := kvs[_]
    kv.name == "sha256"
} else {
    kv := kvs[_]
    kv.name == "md5"
}

has_integrity_in_scope(all_kvs, src_kv) {
    some k
    kv := all_kvs[k]
    k != array.indexof([v | v := all_kvs[_]], src_kv)
    contains_pattern(kv.name, integrity_keywords)
    not is_insecure_value(kv.value)
} else {
    src_kv.name == "baseurl"
    some k
    kv := all_kvs[k]
    contains_pattern(kv.name, {"gpgcheck", "repo_gpgcheck"})
    not is_insecure_value(kv.value)
} else {
    src_kv.name == "baseurl"
    some k
    kv := all_kvs[k]
    kv.name == "gpgkey"
}