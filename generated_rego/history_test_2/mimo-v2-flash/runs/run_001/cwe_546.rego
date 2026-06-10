package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check comments in the UnitBlock
    comment := parent.comments[_]
    
    # Define suspicious keywords for CWE-546
    suspicious_keywords := {"BUG", "HACK", "FIXME", "LATER", "LATER2", "TODO", "WORKAROUND", "TEMPORARY", "XXX", "SECURITY_ISSUE", "HARDcoded", "SKIP_CHECK", "INCOMPLETE", "NOTE"}
    
    # Check if comment content contains any suspicious keyword (case-insensitive)
    contains_suspicious_keyword(comment.content, suspicious_keywords)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comment contains keywords that indicate incomplete functionality, security gaps, or technical debt. (CWE-546)"
    }
}

contains_suspicious_keyword(content, keywords) {
    # Convert content to uppercase for case-insensitive matching
    upper_content := upper(content)
    keyword := keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b", [keyword]), upper_content)
} else {
    # Alternative check using contains from glitch_lib
    keyword := keywords[_]
    glitch_lib.contains(content, keyword)
}