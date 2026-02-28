package glitch

import data.glitch_lib

suspicious_patterns = {
    "BUG", "HACK", "FIXME", "LATER", "LATER2", "TODO",
    "missing security", "incomplete check", "not secure", "vulnerability", "bypass", "hardcoded credentials", "no validation", "skip security",
    "workaround", "temporary fix", "kludge", "quick hack", "legacy", "debt", "error handling missing", "performance issue", "no stored procedure",
    "should be fixed", "might break", "risky", "verify this", "edge case not handled", "assumes", "trusts input", "no authentication", "default deny missing"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    suspicious_comment_content(comment)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found that may indicate security issues. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    suspicious_node(node)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment found in code element that may indicate security issues. (CWE-546)"
    }
}

suspicious_comment_content(comment) {
    pattern := suspicious_patterns[_]
    glitch_lib.contains(comment.content, pattern)
}

suspicious_node(node) {
    node.ir_type == "String"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.value, pattern)
}

suspicious_node(node) {
    node.ir_type == "VariableReference"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.value, pattern)
}

suspicious_node(node) {
    node.ir_type == "Sum"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.code, pattern)
}

suspicious_node(node) {
    node.ir_type == "AtomicUnit"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.code, pattern)
}

suspicious_node(node) {
    node.ir_type == "MethodCall"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.code, pattern)
}

suspicious_node(node) {
    node.ir_type == "UnitBlock"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.code, pattern)
}

suspicious_node(node) {
    node.ir_type == "Attribute"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.code, pattern)
}

suspicious_node(node) {
    node.ir_type == "BlockExpr"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.code, pattern)
}

suspicious_node(node) {
    node.ir_type == "Comment"
    pattern := suspicious_patterns[_]
    glitch_lib.contains(node.content, pattern)
}