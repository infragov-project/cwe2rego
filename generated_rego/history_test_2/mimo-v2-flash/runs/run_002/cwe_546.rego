package glitch

import data.glitch_lib

suspicious_patterns := {
    "TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "TEMP", "WORKAROUND", "XXX", "OPTIMIZE", "DEPRECATED", "NOTE",
    "MISSING SECURITY", "INCOMPLETE", "NOT SECURE", "HARD-CODED", "BYPASS", "VULNERABLE",
    "NO AUTH", "NO VALIDATION", "NO ENCRYPTION", "INSECURE DEFAULT", "DEBUG MODE"
}

contains_suspicious_keyword(content) {
    pattern := suspicious_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), content)
}

Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Comment"
    contains_suspicious_keyword(node.content)
    
    parent_unit_block := glitch_lib._gather_parent_unit_blocks[_]
    parent_unit_block.path != ""
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent_unit_block.path,
        "description": "Suspicious comment found that may indicate unresolved security risks or technical debt (CWE-546)."
    }
}