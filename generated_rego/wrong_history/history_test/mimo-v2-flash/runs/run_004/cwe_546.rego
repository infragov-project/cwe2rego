package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "WORKAROUND", "TEMPORARY", "DEBUG", "XXX"}

Glitch_Analysis[result] {
    # Find all Comment nodes in the IR
    walk(input, [path, node])
    node.ir_type == "Comment"
    
    # Check if comment content contains any suspicious keywords (case-insensitive)
    contains_suspicious_keyword(node.content)
    
    # Get parent UnitBlock for path information
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment found - Comment contains keywords that indicate incomplete or insecure code (CWE-546)"
    }
}

contains_suspicious_keyword(content) {
    # Convert to lowercase for case-insensitive matching
    lower_content := lower(content)
    keyword := suspicious_keywords[_]
    contains(lower_content, lower(keyword))
}

# Helper function to check if string contains substring
contains(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}