# Contributing to Aegis Protocol

Thank you for your interest in contributing. Aegis Protocol is open source under the MIT license and welcomes contributions from the community.

## Before you start

- Check the [open issues](https://github.com/veris-inc/aegis-protocol/issues) to see if your idea or bug is already tracked
- For spec changes, open a discussion issue first — protocol changes affect all implementations
- For bug fixes and small improvements, a PR is fine without prior discussion

## Development setup

```bash
git clone https://github.com/veris-inc/aegis-protocol.git
cd aegis-protocol
npm install
npm run build
npm run test
```

## Pull request checklist

- [ ] Tests pass (`npm run test`)
- [ ] New behavior has test coverage
- [ ] TypeScript compiles without errors (`npm run build`)
- [ ] Public API changes are reflected in the relevant `README.md`
- [ ] Commit messages are clear and describe the change

## Reporting security vulnerabilities

Please **do not** open a public issue for security vulnerabilities. Email **security@verisaegis.com** with details. We will respond within 48 hours.

## Code of conduct

Be direct, be constructive, be respectful. We are building critical infrastructure and hold the code to a high standard — reviewers will push back on things that don't meet the bar. That's not personal; it's how good infrastructure gets built.
