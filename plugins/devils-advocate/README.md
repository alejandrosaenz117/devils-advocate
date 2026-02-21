![The Devil's Advocate Banner](./banner.png)

**A Claude Code plugin for adversarial security and architectural code review.**

When consensus forms, it is a sign of danger. The Devil's Advocate challenges certainty by finding what lies dormant in your code. The collapse. The breach. The failure waiting to unfold. Prepare.

> "If nine of us arrive at the same conclusion, it was the duty of the tenth man to disagree. No matter how improbable it may seem, the tenth man had to prepare on the assumption that the other nine were wrong."
>
> — World War Z

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-Plugin-blueviolet.svg)](https://claude.ai/code)
![Version 0.2.0](https://img.shields.io/badge/Version-0.2.0-green.svg)

---

## What is The Devil's Advocate?

The Devil's Advocate turns Claude into an implacable examiner of your systems. It peers into the fog, the hidden paths, the defenses you think protect you. It reveals where light fails and why the systems you trust will collapse under the weight they cannot see.

### What It Does

- **Identifies security threats** such as auth/authz violations, trust boundary collapse, injection surfaces, credential exposure
- **Finds architectural fragilities** that enable attacks: hidden dependencies, edge-case cascades, resource exhaustion
- **Traces failure cascades** from initial weakness to collapse
- **Reveals the bonfire you thought protected you.** Shows concrete hardening: architectural patterns, security controls, observability, resilience strategies
- **Never gives LGTM.** Every review finds the darkness you did not see coming and shows you how to build ramparts against it.

### What It Does NOT Do

- Style or syntax checking (that's what linters are for)
- Code formatting or refactoring suggestions
- Nitpicking or cosmetic improvements
- Generic "best practices" advice

---

## Installation

Add the marketplace and install the plugin:

```bash
/plugin marketplace add alejandrosaenz117/bonfires-marketplace
/plugin install devils-advocate@bonfires-marketplace
```

---

## Two Ways to Summon The Devil's Advocate

### 1. Skill: Contextual Trigger

The Devil's Advocate activates when you ask for adversarial review.

```
user: "Give me an adversarial review of this payment processing code"
user: [paste code]

# The Devil's Advocate skill produces a four-section review
```

**Trigger phrases:**

- "devil's advocate review"
- "what could go wrong with this?"
- "summon the devil's advocate"
- "challenge the plan"
- "adversarial review"

### 2. Command: Explicit On-Demand

Use `/devils-advocate` to summon an explicit adversarial review.

```
/devils-advocate src/api/payment-service.ts
/devils-advocate
# (paste your architecture description)

/devils-advocate recent
# Analyzes your recent git changes
```

The command uses `model: opus` for maximum depth and clarity. The skill uses `model: inherit` to respect your model choice.

---

## The Four-Section Review Output

Every review from The Devil's Advocate is a four-stage descent. It bypasses the "LGTM" instinct to find the point where the system fails.

### 1. The Contradiction

Name the "Perfect Plan" assumption and the hard truth that violates it.

### 2. The Fragility Vector

Expose the architectural rot (hidden dependencies, cascading failures) that turns a minor flaw into catastrophe.

### 3. The Black Swan Scenario

Simulate one specific, devastating failure. The "unlikely" scenario your team is already ignoring.

### 4. The Mitigation Strategy

Provide concrete architectural hardening. The ramparts required to survive the storm.

---

## Project Structure

```
plugins/devils-advocate/
├── .claude-plugin/
│   └── plugin.json              # Plugin metadata
├── agents/
│   └── devils-advocate.md       # Proactive agent
├── commands/
│   └── review.md                # Explicit command interface
├── skills/
│   └── devils-advocate/
│       ├── SKILL.md             # Contextual auto-triggered skill
│       └── references/
│           └── review-rubric.md # Detailed patterns and mitigation strategies
├── banner.png                   # Plugin banner
└── README.md                    # This file
```

---

## Model Selection

The Devil's Advocate adapts to your preference:

| Surface     | Default   | Alternatives                                                                                         |
| ----------- | --------- | ---------------------------------------------------------------------------------------------------- |
| **Skill**   | `inherit` | Contextual trigger respects your baseline model.                                                     |
| **Command** | `opus`    | Use `/devils-advocate` for full depth. Set `model: sonnet` in `.claude` for faster, lighter reviews. |

The command defaults to Opus for maximum adversarial reasoning. Sonnet is faster and lighter for rapid reviews on straightforward code. The skill inherits your model choice to avoid surprise costs.

---

## Contributing

The Devil's Advocate improves through community refinement. Contribute new fragility vectors, Black Swan scenarios, and mitigation patterns.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines on:

- Adding new fragility vector patterns
- Submitting Black Swan scenario templates
- Improving security coverage
- Enhancing mitigation strategies

---

## Security and Responsible Disclosure

Found a vulnerability in The Devil's Advocate itself (e.g., a prompt injection technique to bypass the mandate)?

See [SECURITY.md](../../SECURITY.md) for responsible disclosure guidelines.

---

## License

MIT License. See [LICENSE](../../LICENSE) for details. Created independently, on personal time, unrelated to any employer's business.

---

## Questions?

- Open a [GitHub Discussion](../../discussions) for questions
- Report bugs as [Issues](../../issues)
- Contribute with [Pull Requests](../../pulls)

---

**The Devil's Advocate: See the darkness before it sees you.**
