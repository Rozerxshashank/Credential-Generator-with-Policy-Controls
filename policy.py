# policy.py
# simple rules for the credential maker (no typing module, easy to read)

# the policy dictionary
POLICY = {
    "allowed_types": ["api_key"],

    "api_key": {
        "min_length": 32,         # token must be at least 32 characters
        "ttl_max_seconds": 86400, # max expiry = 24 hours
        "require_approval_scopes": [
            "admin",   # exact match needs approval
            "write:*"  # prefix match: anything starting with "write:" needs approval
        ]
    },

    "quotas": {
        "max_active_per_principal": 5   # max 5 active keys per user
    }
}


def validate_request(req):
    #Check if request follows basic rules.
   #Returns: (True, "ok") or (False, "reason")
    ctype = req.get("type", "api_key")
    if ctype not in POLICY["allowed_types"]:
        return False, "type_not_allowed"

    api = POLICY["api_key"]

    if req.get("length", 40) < api["min_length"]:
        return False, "length_too_short"

    if req.get("ttl_seconds", 3600) > api["ttl_max_seconds"]:
        return False, "ttl_too_long"

    return True, "ok"


def requires_approval(scopes):
    #Check if any scope is sensitive and needs approval.
    #~Returns: (True, "reason") or (False, "ok")
    rules = POLICY["api_key"]["require_approval_scopes"]

    # if scopes is None or not a list, treat as empty list
    if not scopes:
        return False, "ok"

    for s in scopes:
        for rule in rules:
            # prefix rule (ends with *)
            if rule.endswith("*"):
                prefix = rule[:-1]
                if s.startswith(prefix):
                    return True, "needs_approval_prefix_" + rule

            # exact match
            if s == rule:
                return True, "needs_approval_exact_" + rule

    return False, "ok"
