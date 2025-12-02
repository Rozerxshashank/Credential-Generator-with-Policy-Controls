from typing import List, Tuple
# these are the rules
POLICY = {
    "allowed_types": ["api_key"],

    "api_key": {
        "min_length": 32,        # token must be at least 32 characters
        "ttl_max_seconds": 86400,  # max expiry = 24 hours
        "require_approval_scopes": [
            "admin",    # needs approval
            "write:*"   # anything starting with write: needs approval
        ]
    },

    "quotas": {
        "max_active_per_principal": 5   # max 5 active keys per user
    }
}


def validate_request(req: dict) -> Tuple[bool, str]:
    """Check if request follows basic rules."""
    ctype = req.get("type", "api_key")
    if ctype not in POLICY["allowed_types"]:
        return False, "type_not_allowed"

    api = POLICY["api_key"]

    if req.get("length", 40) < api["min_length"]:
        return False, "length_too_short"

    if req.get("ttl_seconds", 3600) > api["ttl_max_seconds"]:
        return False, "ttl_too_long"

    return True, "ok"


def requires_approval(scopes: List[str]) -> Tuple[bool, str]:
    """Check if any scope is sensitive and needs approval."""
    rules = POLICY["api_key"]["require_approval_scopes"]

    for s in scopes:
        for rule in rules:

            if rule.endswith("*"):  # prefix match
                prefix = rule[:-1]
                if s.startswith(prefix):
                    return True, f"needs_approval_prefix_{rule}"

            if s == rule:
                return True, f"needs_approval_exact_{rule}"

    return False, "ok"
