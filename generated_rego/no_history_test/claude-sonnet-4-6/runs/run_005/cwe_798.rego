package glitch

import data.glitch_lib

is_nonempty_literal_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not regex.match(`^\s*$`, value.value)
    not regex.match(`^\$[\{\(]`, value.value)
    not regex.match(`^<%`, value.value)
}

is_sensitive_name(name) {
    regex.match(`(?i).*(password|passwd|pwd|passphrase|secret|token|api[_.\-]?key|apikey|private[_.\-]?key|encryption[_.\-]?key|signing[_.\-]?key|rsa[_.\-]?key|ssh[_.\-]?key|hmac[_.\-]?key|access[_.\-]?key|keystore|truststore|certificate|credential).*`, name)
}

is_sensitive_name(name) {
    regex.match(`(?i)(^|[^a-zA-Z])user([^a-zA-Z]|$)`, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_nonempty_literal_string(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive attribute contains a literal string value instead of a secret reference. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_name(v.name)
    is_nonempty_literal_string(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive variable contains a literal string value instead of a secret reference. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`(?s)-----BEGIN\s`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Inline cryptographic key material (PEM block) detected. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`(?i).*(pwd=|password=)[^;\s"']+.*`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Connection string contains embedded credentials. (CWE-798)"
    }
}