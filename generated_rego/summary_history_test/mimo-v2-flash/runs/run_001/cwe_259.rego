package glitch

import data.glitch_lib
import future.keywords.in

password_keywords_pattern := `(?i)\b(password|secret|token|pass|credential|sha512_password|keystore_password|truststore_password|key)\b`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    some entry in n.value
    entry.key.ir_type == "String"
    regex.match(password_keywords_pattern, entry.key.value)
    entry.value.ir_type == "String"
    entry.value.value != ""
    not endswith(entry.value.value, ".keystore")
    not endswith(entry.value.value, ".jks")
    not endswith(entry.value.value, ".p12")
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Hard-coded password in hash entry - Avoid hard-coding passwords, tokens, or other secrets in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    regex.match(password_keywords_pattern, n.name)
    n.value.ir_type == "String"
    n.value.value != ""
    not endswith(n.value.value, ".keystore")
    not endswith(n.value.value, ".jks")
    not endswith(n.value.value, ".p12")
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": "Hard-coded password in variable - Avoid hard-coding passwords, tokens, or other secrets in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    regex.match(password_keywords_pattern, n.name)
    n.value.ir_type == "String"
    n.value.value != ""
    not endswith(n.value.value, ".keystore")
    not endswith(n.value.value, ".jks")
    not endswith(n.value.value, ".p12")
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": "Hard-coded password in attribute - Avoid hard-coding passwords, tokens, or other secrets in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Array"
    some element in n.value
    element.ir_type == "String"
    element.value != ""
    regex.match(`(?i)(password|secret|token|pass|credential|sha512_password|keystore_password|truststore_password|key)`, element.value)
    not endswith(element.value, ".keystore")
    not endswith(element.value, ".jks")
    not endswith(element.value, ".p12")
    result := {
        "type": "sec_hard_pass",
        "element": element,
        "path": parent.path,
        "description": "Hard-coded password in array element - Avoid hard-coding passwords, tokens, or other secrets in IaC scripts. (CWE-259)"
    }
}