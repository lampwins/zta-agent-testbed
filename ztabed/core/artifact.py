"""Release artifact: the corpus, its schema, and a manifest that pins both.

If the corpus is the contribution then it has to be citable, and a citable
corpus needs three things a directory of Python files does not give you: a stable
serialised form, a content hash so a reported result can be tied to the exact
cases that produced it, and a schema so someone can build on it without reading
the generator.

The manifest also carries the difficulty distribution and pairing structure. That
is what lets a reader check the claim that difficulty was assigned before any arm
ran, rather than taking it on trust -- the digest of a corpus published before a
run cannot be reconciled with one relabelled after it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .corpus import BENIGN, MALICIOUS, Corpus

SCHEMA_VERSION = "1.0"
LICENSE = "CC-BY-4.0"


def action_context_schema() -> Dict[str, Any]:
    """JSON Schema for the ActionContext a PDP rules on.

    Emitted from code rather than transcribed, so a paper figure cannot drift
    away from what the evaluation actually passes to a decision point.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ActionContext",
        "description": (
            "Everything a Policy Decision Point sees about one pending action. A PDP has "
            "no other channel: no conversation, no model, no side information."
        ),
        "type": "object",
        "required": ["agent_name", "tool", "call", "original_request"],
        "properties": {
            "agent_name": {"type": "string", "description": "Which agent is requesting the action."},
            "original_request": {
                "type": "string",
                "description": "The task the human principal issued. Trusted ground truth for intent.",
            },
            "agent_rationale": {
                "type": "string",
                "description": (
                    "The agent's own account of why it is acting. UNTRUSTED: an agent under "
                    "injected instructions produces a confident rationale for the attacker's action."
                ),
            },
            "principal": {
                "type": ["object", "null"],
                "description": "Who the action is on behalf of.",
                "properties": {
                    "id": {"type": "string"},
                    "display_name": {"type": "string"},
                    "roles": {"type": "array", "items": {"type": "string"}},
                    "authenticated": {"type": "boolean"},
                    "auth_method": {"type": "string"},
                },
            },
            "tool": {
                "type": "object",
                "description": "The capability being invoked, and how its registration was vouched for.",
                "required": ["name", "description"],
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "source": {"type": "string", "description": "Self-declared origin. Not evidence."},
                    "trust_level": {"type": "string", "enum": ["trusted", "unverified", "untrusted"]},
                    "attestation": {
                        "type": "object",
                        "description": "Signing and version-binding evidence for the registration.",
                        "properties": {
                            "signed_by": {"type": ["string", "null"]},
                            "signature_valid": {"type": "boolean"},
                            "approved_version": {"type": "string"},
                            "registered_version": {"type": "string"},
                            "registry": {"type": "string"},
                            "registry_allowlisted": {"type": "boolean"},
                        },
                    },
                },
            },
            "call": {
                "type": "object",
                "required": ["name", "arguments"],
                "properties": {
                    "name": {"type": "string"},
                    "arguments": {"type": "object"},
                    "call_id": {"type": ["string", "null"]},
                },
            },
            "resource": {
                "type": ["object", "null"],
                "description": "What the action touches, in the terms the enforcement point arbitrates.",
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string"},
                    "sensitivity": {
                        "type": "string",
                        "enum": ["public", "internal", "confidential", "restricted"],
                    },
                    "egress": {"type": "boolean", "description": "Does the effect leave the trust boundary?"},
                    "reversible": {"type": "boolean"},
                },
            },
            "provenance": {
                "type": "array",
                "description": (
                    "Where each argument's value came from. Lets a PDP ask whether a value has "
                    "any business being there, rather than only whether it matches a rule."
                ),
                "items": {
                    "type": "object",
                    "required": ["field", "origin", "trust"],
                    "properties": {
                        "field": {"type": "string"},
                        "value_excerpt": {"type": "string"},
                        "origin": {
                            "type": "string",
                            "enum": ["user_request", "tool_output", "agent_generated", "trusted_directory"],
                        },
                        "source_id": {"type": "string"},
                        "trust": {"type": "string", "enum": ["trusted", "unverified", "untrusted"]},
                    },
                },
            },
            "sender_identity": {
                "type": ["object", "null"],
                "description": "Claimed identity for an inter-agent instruction, with key lifecycle state.",
                "properties": {
                    "claimed_sender": {"type": "string"},
                    "payload": {"type": "string", "description": "UNTRUSTED."},
                    "signature": {"type": "string"},
                    "signature_valid": {"type": "boolean"},
                    "sender_registered": {"type": "boolean"},
                    "key_id": {"type": "string"},
                    "key_state": {"type": "string", "enum": ["active", "retired", "revoked"]},
                    "key_age_days": {"type": "integer"},
                    "authorized_scopes": {"type": "array", "items": {"type": "string"}},
                },
            },
            "session": {
                "type": ["object", "null"],
                "properties": {
                    "session_id": {"type": "string"},
                    "step": {"type": "integer"},
                    "prior_actions": {"type": "array", "items": {"type": "string"}},
                    "novel_for_principal": {"type": "boolean"},
                },
            },
        },
    }


def manifest(corpus: Corpus) -> Dict[str, Any]:
    difficulty: Dict[str, Dict[str, int]] = {}
    for case in corpus:
        bucket = difficulty.setdefault(case.difficulty, {MALICIOUS: 0, BENIGN: 0})
        bucket[case.label] += 1

    pairs: Dict[str, List[str]] = {}
    for case in corpus:
        if case.pair_id:
            pairs.setdefault(case.pair_id, []).append(case.case_id)

    per_vector = {}
    for vector in corpus.vectors():
        sub = corpus.filter(vector=vector)
        per_vector[vector] = sub.balance()

    return {
        "schema_version": SCHEMA_VERSION,
        "license": LICENSE,
        "digest": corpus.digest(),
        "case_count": len(corpus),
        "balance": corpus.balance(),
        "by_vector": per_vector,
        "by_difficulty": difficulty,
        "pair_count": len(pairs),
        "paired_cases": {k: sorted(v) for k, v in sorted(pairs.items())},
        "unpaired": sorted(c.case_id for c in corpus if not c.pair_id),
        "note": (
            "Difficulty labels and pair structure are fixed in the corpus source and are "
            "included in the digest. A result reporting this digest was produced against "
            "exactly these labels."
        ),
    }


def write_artifact(corpus: Corpus, out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    cases = out_dir / "corpus.jsonl"
    with cases.open("w") as fh:
        for case in corpus:
            fh.write(json.dumps(case.summary(), sort_keys=True, default=str) + "\n")
    written.append(cases)

    for name, payload in (
        ("manifest.json", manifest(corpus)),
        ("action_context.schema.json", action_context_schema()),
    ):
        path = out_dir / name
        path.write_text(json.dumps(payload, indent=2, default=str))
        written.append(path)

    readme = out_dir / "README.md"
    readme.write_text(
        f"""# ztabed corpus artifact

{len(corpus)} labelled pending actions across {len(corpus.vectors())} attack vectors.
Digest `{corpus.digest()}`. Licensed {LICENSE}.

- `corpus.jsonl` — one labelled case per line.
- `manifest.json` — balance, difficulty distribution, pairing structure.
- `action_context.schema.json` — the structure a Policy Decision Point rules on.

Each case carries a `rationale` justifying its label, a `defeats` field naming the
shortcut it was built to defeat, and, where it has a twin, a `pair_id`. Paired cases
hold every surface feature constant and vary only the fact that authorises the
action, so a detector cannot separate them on form alone.

Regenerate with `python -m ztabed.cli export`.
"""
    )
    written.append(readme)
    return written
