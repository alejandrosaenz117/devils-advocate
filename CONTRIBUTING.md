# Contributing to Devil's Advocate

Thank you for contributing! Devil's Advocate improves through community input: better fragility vectors, sharper Black Swan scenarios, deeper security insight.

## How to Contribute

### Reporting Issues

Found a gap or a flaw in Devil's Advocate's adversarial reasoning?

1. Open a GitHub issue with:
   - The specific code or scenario where Devil's Advocate missed something
   - What fragility vector it relates to (Architectural, Security, Scalability, etc.)
   - Why the current rubric doesn't catch it

### Submitting Improvements

#### Adding New Fragility Vector Patterns

Edit `skills/devils-advocate/references/review-rubric.md`:

1. Identify a category of failure mode not yet covered
2. Add it under the appropriate Fragility Vector section
3. Include:
   - Clear description of the fragility
   - One or two real-world examples
   - Contradiction pattern (developer assumption versus reality)
   - Specific code patterns to look for
4. Submit a PR with your addition

#### Adding Black Swan Scenarios

Add templates to `skills/devils-advocate/references/review-rubric.md`:

1. Write a high-impact scenario under "Black Swan Examples"
2. Include:
   - Unlikely but devastating trigger (e.g., "user with 50,000 legacy records during peak traffic")
   - Why current code fails in this case
   - The security or operational impact
3. Focus on scenarios that are plausible but not obvious

#### Improving Security Coverage

The Security Fragility Vectors section welcomes depth:

- Auth/authz boundary violations
- Trust boundary collapse
- Injection surfaces at scale (including prompt injection)
- Cryptographic assumptions
- Supply chain fragility
- Agentic system security (agents, tools, external integrations)
- AI model reliance and hallucination risks
- LLM-specific vulnerabilities (jailbreaks, data leakage, cost amplification)

If you work in security, AI safety, or have experience with OWASP Top 10 vulnerabilities, that's the exact place to contribute.

#### Enhancing Mitigation Patterns

Add concrete architectural patterns to counter identified fragilities:

- Circuit breakers, bulkheads, timeout strategies
- Idempotency keys and deduplication
- Zero-trust boundaries and least-privilege design
- Threat modeling frameworks
- Observability and alerting patterns

### How to Submit a PR

1. Fork the repository
2. Create a branch for your changes: `git checkout -b add-fragility-vector-name`
3. Make your edits to the relevant file(s)
4. Commit with a clear message: `git commit -m "Add [fragility vector/scenario] to review-rubric"`
5. Push to your fork: `git push origin add-fragility-vector-name`
6. Open a pull request against `main` with a description of your addition

### PR Checklist

Before submitting:

- [ ] Does this strengthen the adversarial lens (architecture, security, scalability)?
- [ ] Does this avoid style/syntax concerns (linting, formatting)?
- [ ] Is the example or scenario concrete and plausible?
- [ ] Does the contribution follow the existing writing style (clinical, direct)?
- [ ] Have I tested the new pattern with real code examples?

### Code of Conduct

Be respectful. Disagreement is part of adversarial review — this includes discussion of proposed changes.

### Questions?

Open a discussion or issue. We value clarity.

---

Thank you for strengthening Devil's Advocate.
