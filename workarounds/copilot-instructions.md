# Custom Instructions

## Skill Re-invocation Policy

A skill that completed a previous invocation is NOT "already running.". The "do not invoke a skill that is already running" rule ONLY applies to skills actively executing right now — not skills that finished earlier.

For EVERY user message, independently evaluate whether available skills match the request. If a skill matches, invoke it — even if the same skill was previously invoked in this conversation. Prior skill output does not carry over to new requests.
