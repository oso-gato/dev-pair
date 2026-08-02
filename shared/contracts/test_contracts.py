#!/usr/bin/env python3
"""Contract tests for shared/contracts — the platform's versioned grammars.

Runs the real JSON Schema validator (no mocks): every example instance must be
ACCEPTED by its schema, and every mutation row must be REFUSED. The mutation
rows are the in-suite mutation check (P8): they prove each constraint binds —
a future schema edit that silently drops a constraint (e.g. unbinding a verdict
from its sha) turns one of these rows green and fails the suite.

Consumer law under test (P7): an unknown grammar or version, an unknown field,
or a missing required field is refused — never mis-parsed.

Requires: python3-jsonschema (Fedora dnf package, provenance L1).
Run: python3 shared/contracts/test_contracts.py
"""

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

HERE = Path(__file__).resolve().parent
EXAMPLES = HERE / "examples"


def load(name):
    return json.loads((HERE / name).read_text())


def load_example(name):
    return json.loads((EXAMPLES / name).read_text())


SCHEMAS = {
    "ticket-envelope": load("ticket-envelope.v1.schema.json"),
    "verdict": load("verdict.v1.schema.json"),
    "refresh-manifest": load("refresh-manifest.v1.schema.json"),
    "lineage-manifest": load("lineage-manifest.v1.schema.json"),
}

VALIDATORS = {k: Draft202012Validator(v) for k, v in SCHEMAS.items()}

# Every example ships valid. (grammar-name, example-file)
POSITIVE = [
    ("ticket-envelope", "ticket-envelope.verdict-request.v1.json"),
    ("ticket-envelope", "ticket-envelope.objective-lock.v1.json"),
    ("verdict", "verdict.green.v1.json"),
    ("refresh-manifest", "refresh-manifest.dev-container.v1.json"),
    ("lineage-manifest", "lineage-manifest.claudebox.v1.json"),
    ("lineage-manifest", "lineage-manifest.kimibox.v1.json"),
    ("lineage-manifest", "lineage-manifest.non-admission.v1.json"),
]


def mutate(instance, fn):
    m = copy.deepcopy(instance)
    fn(m)
    return m


# (grammar, label, instance) — every row must be REFUSED.
NEGATIVE = []


def neg(grammar, label, instance):
    NEGATIVE.append((grammar, label, instance))


# --- fail-safe consumer law: unknown grammar / version / field ---
for g, ex in POSITIVE:
    inst = load_example(ex)
    neg(g, f"{g}: version bump refused",
        mutate(inst, lambda m: m.__setitem__("v", 99)))
    neg(g, f"{g}: unknown grammar name refused",
        mutate(inst, lambda m: m.__setitem__("grammar", "not-a-grammar")))
    neg(g, f"{g}: unknown extra field refused",
        mutate(inst, lambda m: m.__setitem__("surprise", True)))

# --- ticket-envelope ---
t = load_example("ticket-envelope.verdict-request.v1.json")
neg("ticket-envelope", "verdict-request without sha refused",
    mutate(t, lambda m: m.pop("sha")))
neg("ticket-envelope", "empty scope refused",
    mutate(t, lambda m: m.__setitem__("scope", [])))
neg("ticket-envelope", "missing session namespace refused",
    mutate(t, lambda m: m.pop("session")))

# --- verdict: testimony is not evidence; sha binding is mandatory ---
v = load_example("verdict.green.v1.json")
neg("verdict", "verdict without evidence refused",
    mutate(v, lambda m: m.__setitem__("evidence", [])))
neg("verdict", "verdict unbound from sha refused",
    mutate(v, lambda m: m.pop("sha")))
neg("verdict", "verdict without non-author identity refused",
    mutate(v, lambda m: m.pop("by")))
neg("verdict", "non-sha value in sha field refused",
    mutate(v, lambda m: m.__setitem__("sha", "latest")))

# --- refresh-manifest: rollback and read-back checks are mandatory ---
r = load_example("refresh-manifest.dev-container.v1.json")
neg("refresh-manifest", "dev-container refresh without image refused",
    mutate(r, lambda m: m.pop("image")))
neg("refresh-manifest", "refresh without rollback refused",
    mutate(r, lambda m: m.pop("rollback")))
neg("refresh-manifest", "refresh without verify checks refused",
    mutate(r, lambda m: m.__setitem__("verify", [])))
neg("refresh-manifest", "session-policy outside resume/defer refused",
    mutate(r, lambda m: m.__setitem__("session-policy", "yolo")))

# --- lineage-manifest: the admission contract binds ---
lk = load_example("lineage-manifest.kimibox.v1.json")   # L3
neg("lineage-manifest", "L3 provenance without grade refused",
    mutate(lk, lambda m: m["provenance"].pop("grade")))
neg("lineage-manifest", "provenance without pin refused",
    mutate(lk, lambda m: m["provenance"].pop("pin")))
ln = load_example("lineage-manifest.non-admission.v1.json")
neg("lineage-manifest", "non-admission without reason refused",
    mutate(ln, lambda m: m.pop("reason")))
neg("lineage-manifest", "empty state-outside refused",
    mutate(ln, lambda m: m.__setitem__("state-outside", [])))


def main():
    failures = []

    for name, schema in SCHEMAS.items():
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as e:
            failures.append(f"schema {name} is not a valid Draft 2020-12 schema: {e.message}")

    for grammar, ex in POSITIVE:
        errors = list(VALIDATORS[grammar].iter_errors(load_example(ex)))
        if errors:
            failures.append(f"ACCEPT row failed — {ex} must validate: "
                            + "; ".join(e.message for e in errors))

    for grammar, label, instance in NEGATIVE:
        errors = list(VALIDATORS[grammar].iter_errors(instance))
        if not errors:
            failures.append(f"REFUSE row failed — {label}: instance was accepted")

    total = len(POSITIVE) + len(NEGATIVE)
    if failures:
        print(f"FAIL — {len(failures)} of {total} rows:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS — {total} rows ({len(POSITIVE)} accept, {len(NEGATIVE)} refuse), "
          f"{len(SCHEMAS)} schemas meta-valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
