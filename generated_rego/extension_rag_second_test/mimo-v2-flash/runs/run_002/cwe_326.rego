package glitch

import data.glitch_lib

# Detect weak encryption configuration in Ansible
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for weak encryption attributes in Ansible (e.g., hash filter with sha1)
    attr.value.ir_type == "FunctionCall"
    regex.match("(?i)hash|md5|sha1", attr.value.name)
    # Check if the algorithm is weak (sha1, md5)
    some weak_algo
    attr.value.args[_].ir_type == "String"
    weak_algo := attr.value.args[_].value
    regex.match("(?i)md5|sha1|rc4|des|3des|ssl|tls\\s*1\\.[01]|ecb", weak_algo)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm used in Ansible task. (CWE-326)"
    }
}

# Detect weak encryption in Ansible vars_prompt (e.g., encrypt: md5_crypt)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    # Check for weak encryption in variable values (strings)
    v.value.ir_type == "String"
    regex.match("(?i)md5_crypt|md5|sha1|des|3des|rc4", v.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable definition. (CWE-326)"
    }
}

# Detect weak cipher suites in Chef attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    # Check for weak cipher suites in string values
    v.value.ir_type == "String"
    regex.match("(?i)TLS_RSA_WITH_AES_128_CBC_SHA|TLS_RSA_WITH_3DES_EDE_CBC_SHA|TLS_DHE_RSA_WITH_AES_128_CBC_SHA", v.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite configured. (CWE-326)"
    }
}

# Detect insufficient key sizes in Chef attributes (e.g., key length < 2048)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    # Check for insufficient key sizes in integer values
    v.value.ir_type == "Integer"
    v.value.value < 2048
    v.value.value > 0

    # Exclude non-cryptographic key sizes (e.g., timeouts, thresholds)
    not regex.match("(?i)timeout|threshold|size|length|count|num|index", v.name)

    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key size detected. (CWE-326)"
    }
}