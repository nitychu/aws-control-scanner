import json
import os
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

CACHE_PATH = "output/explanations.json"
MODEL = "claude-sonnet-4-5"

PROMPT = """You are writing for a cloud security audit report.

Control: {control_id} — {title}
Status: {status}
Evidence: {evidence}

Write two short paragraphs, no headings, no preamble:
1. The risk this finding represents, in plain language a non-technical
   stakeholder would understand.
2. The specific remediation steps an engineer should take.

Be concrete. Do not restate the control title. Under 120 words total."""


def _load_cache():
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH) as f:
            return json.load(f)
    return {}


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)


def enrich(findings):
    """Add a plain-English explanation to each FAIL finding."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("No ANTHROPIC_API_KEY found — skipping explanations.")
        return findings
    cache = _load_cache()
    client = Anthropic()

    for f in findings:
        if f["status"] != "FAIL":
            continue

        key = f"{f['control_id']}::{f['status']}"

        if key not in cache:
            message = client.messages.create(
                model=MODEL,
                max_tokens=400,
                messages=[{
                    "role": "user",
                    "content": PROMPT.format(
                        control_id=f["control_id"],
                        title=f["title"],
                        status=f["status"],
                        evidence=f["evidence"],
                    ),
                }],
            )
            cache[key] = message.content[0].text.strip()

        f["explanation"] = cache[key]

    _save_cache(cache)
    return findings
