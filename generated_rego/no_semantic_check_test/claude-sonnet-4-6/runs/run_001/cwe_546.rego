package glitch

import data.glitch_lib

suspicious_comment_pattern := "(?i)(TODO|FIXME|LATER|WIP|PENDING|REVISIT|HACK|WORKAROUND|KLUDGE|\\bTEMP\\b|TEMPORARY|\\bBUG\\b|XXX|BROKEN|DEFECT|\\bFLAW\\b|VULNERABILITY|SECURITY ISSUE|KNOWN ISSUE|DISABLED|BYPASS|\\bSKIP\\b|\\bIGNORE\\b|TURNED OFF|NOT ENFORCED|REMOVE BEFORE PROD|DEV ONLY|TESTING ONLY|NOT FOR PROD|REPLACE THIS|CHANGE ME|PLACEHOLDER|HARD-CODED|HARDCODED|DEFAULT PASSWORD|\\bDUMMY\\b|\\bFAKE\\b|EXAMPLE ONLY|FILL IN|INSERT REAL|TOO PERMISSIVE|OPEN FOR NOW|RESTRICT LATER|TIGHTEN THIS|WIDE OPEN|OVERLY BROAD|LOCK DOWN LATER|SHORTCUT|QUICK.FIX|BAND.AID|DIRTY FIX|NOT IDEAL)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_comment_pattern, comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments indicating deferred security decisions, disabled controls, acknowledged insecure workarounds, or incomplete configurations that may never be revisited. (CWE-546)"
    }
}