# AI Code Review Tool

A lightweight, dependency-free code review tool that analyzes git diffs and outputs structured review comments with severity labels and risk scoring.

## Features

- **Severity-labeled comments**: Critical, Required, Nit, Optional, FYI
- **Risk scoring**: 0-10 scale with MINIMAL/LOW/MEDIUM/HIGH levels
- **Multiple output formats**: Console (default), JSON, Markdown
- **Multiple input sources**: Diff files, GitHub PR URLs, stdin
- **Zero dependencies**: Pure Node.js stdlib
- **Comprehensive rule set**: 40+ rules across 8 categories

## Installation

No installation required — just clone and run:

```bash
git clone <repo>
cd tools/ai-code-review
node index.js --help
```

## Usage

### Review a diff file

```bash
node index.js path/to/changes.diff
```

### Review a GitHub PR

```bash
node index.js --pr https://github.com/owner/repo/pull/123
```

### Pipe from stdin

```bash
git diff main...HEAD | node index.js -
```

### Output formats

```bash
# JSON output
node index.js changes.diff --json > review.json

# Markdown output
node index.js changes.diff --markdown > REVIEW.md
```

### Self-test

```bash
node index.js --test
```

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **Critical** | Security vulnerabilities, data loss risks | Must fix before merge |
| **Required** | Correctness issues, error handling gaps | Should fix before merge |
| **Nit** | Style, minor improvements | Fix if convenient |
| **Optional** | Suggestions, alternatives | Consider |
| **FYI** | Informational, awareness | No action needed |

## Rule Categories

- **Security**: XSS, injection, hardcoded secrets, weak crypto, TLS
- **Correctness**: Type coercion, JSON parsing, assertions, TODOs
- **Error Handling**: Empty catches, unhandled promises
- **Performance**: Nested loops, inefficient patterns
- **Readability**: Long functions, var usage, naming
- **Architecture**: Coupling, global state, deep imports
- **Async**: Sequential awaits, promise anti-patterns
- **Testing**: Missing tests, skipped tests, empty assertions

## Risk Score

The risk score (0-10) is calculated from:
- Severity weights: Critical=10, Required=5, Nit=2, Optional=1, FYI=0.5
- Normalized by file count
- Boosted for critical issues

| Score | Level | Meaning |
|-------|-------|---------|
| 0-2 | MINIMAL | Safe to merge |
| 2-5 | LOW | Minor concerns |
| 5-8 | MEDIUM | Review carefully |
| 8-10 | HIGH | Do not merge without fixes |

## API

```javascript
const { reviewDiff } = require('./index.js');

const result = await reviewDiff(diffText);
// result.files       - parsed file metadata
// result.comments    - array of review comments
// result.riskScore   - { score, level, severityCounts }
// result.summary     - human-readable summary
// result.metadata    - tool info, timestamps
```

## Exit Codes

- `0`: No critical issues found
- `1`: Error (file not found, invalid input, etc.)
- `2`: Critical issues found in the diff

## License

MIT
