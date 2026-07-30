from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from ztabed.core.policy import ActionContext, Control, Decision, PolicyDecision


@dataclass
class SignedEnvelope:
    claimed_sender: str
    payload: str
    signature: str  # hex HMAC-SHA256 over payload, keyed by the claimed sender's secret


def sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


class IdentityVerificationControl(Control):
    """Mitigates agent impersonation / spoofing in a multi-agent system.

    Every inter-agent instruction must arrive as a SignedEnvelope. This
    control verifies the signature against a registry of known agent
    secrets (a stand-in for per-agent keys/certs in a real deployment) --
    mutual authentication instead of trusting a free-text "from" field.
    """

    name = "identity_verification"

    def __init__(self, known_secrets: dict, trusted_senders: set):
        self.known_secrets = known_secrets  # {agent_name: secret}
        self.trusted_senders = trusted_senders  # agents allowed to issue this kind of instruction

    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        envelope = ctx.sender_identity
        if envelope is None:
            return PolicyDecision(Decision.DENY, "no signed envelope attached to this instruction", self.name)

        claimed = envelope.get("claimed_sender")
        signature = envelope.get("signature")
        payload = envelope.get("payload", "")

        if claimed not in self.trusted_senders:
            return PolicyDecision(Decision.DENY, f"'{claimed}' is not a trusted sender for this action", self.name)

        secret = self.known_secrets.get(claimed)
        if secret is None or not hmac.compare_digest(sign(secret, payload), signature or ""):
            return PolicyDecision(Decision.DENY, f"signature verification failed for claimed sender '{claimed}'", self.name)

        return PolicyDecision(Decision.ALLOW, f"signature verified for '{claimed}'", self.name)
