#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { execSync } = require('child_process');

// ─── Severity Levels ────────────────────────────────────────────────────────
const SEVERITY = {
  CRITICAL: 'Critical',
  REQUIRED: 'Required',
  NIT: 'Nit',
  OPTIONAL: 'Optional',
  FYI: 'FYI',
};

const SEVERITY_ORDER = ['Critical', 'Required', 'Nit', 'Optional', 'FYI'];

// ─── Risk Scoring ───────────────────────────────────────────────────────────
const RISK_WEIGHTS = {
  Critical: 10,
  Required: 5,
  Nit: 2,
  Optional: 1,
  FYI: 0.5,
};

// ─── Analysis Rules ─────────────────────────────────────────────────────────
// Each rule: { pattern, severity, category, message, suggestion }
const RULES = [
  // ── Security ──────────────────────────────────────────────────────────────
  {
    pattern: /eval\s*\(/g,
    severity: SEVERITY.CRITICAL,
    category: 'Security',
    message: 'Use of eval() can lead to code injection vulnerabilities',
    suggestion: 'Replace eval() with JSON.parse() or a safer alternative',
  },
  {
    pattern: /innerHTML\s*=/g,
    severity: SEVERITY.CRITICAL,
    category: 'Security',
    message: 'Direct innerHTML assignment can lead to XSS attacks',
    suggestion: 'Use textContent or a DOM sanitization library',
  },
  {
    pattern: /dangerouslySetInnerHTML/g,
    severity: SEVERITY.CRITICAL,
    category: 'Security',
    message: 'dangerouslySetInnerHTML bypasses React XSS protections',
    suggestion: 'Sanitize HTML content or use safe rendering methods',
  },
  {
    pattern: /child_process|execSync|exec\(|spawn\(/g,
    severity: SEVERITY.REQUIRED,
    category: 'Security',
    message: 'Process execution detected — validate all inputs to prevent command injection',
    suggestion: 'Use execFile with argument arrays, never shell strings with user input',
  },
  {
    pattern: /password\s*=\s*['"][^'"]+['"]|api[_-]?key\s*=\s*['"][^'"]+['"]|secret\s*=\s*['"][^'"]+['"]/gi,
    severity: SEVERITY.CRITICAL,
    category: 'Security',
    message: 'Hardcoded credential or secret detected',
    suggestion: 'Move secrets to environment variables or a secrets manager',
  },
  {
    pattern: /SELECT\s+.*\+\s+|INSERT\s+.*\+\s+|UPDATE\s+.*\+\s+/gi,
    severity: SEVERITY.CRITICAL,
    category: 'Security',
    message: 'Potential SQL injection via string concatenation',
    suggestion: 'Use parameterized queries or prepared statements',
  },
  {
    pattern: /md5|sha1(?!\d)/gi,
    severity: SEVERITY.REQUIRED,
    category: 'Security',
    message: 'Weak cryptographic hash algorithm detected',
    suggestion: 'Use SHA-256 or stronger for hashing; use bcrypt/argon2 for passwords',
  },
  {
    pattern: /Math\.random\(\)/g,
    severity: SEVERITY.REQUIRED,
    category: 'Security',
    message: 'Math.random() is not cryptographically secure',
    suggestion: 'Use crypto.randomBytes() or crypto.randomUUID() for security contexts',
  },
  {
    pattern: /http:\/\//g,
    severity: SEVERITY.REQUIRED,
    category: 'Security',
    message: 'Insecure HTTP URL detected',
    suggestion: 'Use HTTPS for all external connections',
  },
  {
    pattern: /verify\s*:\s*false|rejectUnauthorized\s*:\s*false/g,
    severity: SEVERITY.CRITICAL,
    category: 'Security',
    message: 'TLS/SSL certificate verification disabled',
    suggestion: 'Never disable certificate verification in production',
  },

  // ── Correctness ───────────────────────────────────────────────────────────
  {
    pattern: /==(?!=)/g,
    severity: SEVERITY.REQUIRED,
    category: 'Correctness',
    message: 'Loose equality (==) can cause unexpected type coercion',
    suggestion: 'Use strict equality (===) instead',
  },
  {
    pattern: /!=(?!=)/g,
    severity: SEVERITY.REQUIRED,
    category: 'Correctness',
    message: 'Loose inequality (!=) can cause unexpected type coercion',
    suggestion: 'Use strict inequality (!==) instead',
  },
  {
    pattern: /JSON\.parse\s*\(\s*[^)]*\)(?!\s*catch)/g,
    severity: SEVERITY.REQUIRED,
    category: 'Correctness',
    message: 'JSON.parse without try-catch can throw on invalid input',
    suggestion: 'Wrap JSON.parse in a try-catch block',
  },
  {
    pattern: /parseInt\s*\([^,)]+\)/g,
    severity: SEVERITY.NIT,
    category: 'Correctness',
    message: 'parseInt without radix can produce unexpected results',
    suggestion: 'Always specify the radix: parseInt(value, 10)',
  },
  {
    pattern: /setTimeout\s*\(\s*[^,]+,\s*0\s*\)/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Correctness',
    message: 'setTimeout with 0ms delay is often a code smell',
    suggestion: 'Consider if setImmediate or queueMicrotask is more appropriate',
  },
  {
    pattern: /console\.(log|debug|info)\s*\(/g,
    severity: SEVERITY.NIT,
    category: 'Correctness',
    message: 'Console statement left in code',
    suggestion: 'Remove or replace with a proper logging framework',
  },
  {
    pattern: /TODO|FIXME|HACK|XXX/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Correctness',
    message: 'Unresolved TODO/FIXME comment',
    suggestion: 'Address the TODO or create a tracked issue',
  },
  {
    pattern: /@ts-ignore|@ts-nocheck|eslint-disable/g,
    severity: SEVERITY.REQUIRED,
    category: 'Correctness',
    message: 'Type checking or linting suppression detected',
    suggestion: 'Fix the underlying issue instead of suppressing the error',
  },
  {
    pattern: /as\s+any/g,
    severity: SEVERITY.REQUIRED,
    category: 'Correctness',
    message: 'TypeScript "as any" bypasses type safety',
    suggestion: 'Use proper types or unknown with type guards',
  },
  {
    pattern: /!\s*$/gm,
    severity: SEVERITY.NIT,
    category: 'Correctness',
    message: 'Non-null assertion operator (!) may hide null issues',
    suggestion: 'Consider optional chaining or explicit null checks',
  },

  // ── Error Handling ────────────────────────────────────────────────────────
  {
    pattern: /catch\s*\([^)]*\)\s*\{\s*\}/g,
    severity: SEVERITY.REQUIRED,
    category: 'Error Handling',
    message: 'Empty catch block swallows errors silently',
    suggestion: 'Log the error or re-throw with context',
  },
  {
    pattern: /catch\s*\{\s*\}/g,
    severity: SEVERITY.REQUIRED,
    category: 'Error Handling',
    message: 'Empty catch block swallows errors silently',
    suggestion: 'Log the error or re-throw with context',
  },
  {
    pattern: /\.then\s*\([^)]*\)\s*$/gm,
    severity: SEVERITY.REQUIRED,
    category: 'Error Handling',
    message: 'Promise .then() without .catch() may leave unhandled rejections',
    suggestion: 'Add .catch() or use async/await with try-catch',
  },
  {
    pattern: /process\.on\s*\(\s*['"]uncaughtException['"]/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Error Handling',
    message: 'uncaughtException handler may leave process in inconsistent state',
    suggestion: 'Consider using domain or clustering for error recovery',
  },

  // ── Performance ───────────────────────────────────────────────────────────
  {
    pattern: /for\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*\)/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Performance',
    message: 'Nested loops may indicate O(n²) complexity',
    suggestion: 'Consider if a hash map or index can reduce complexity',
  },
  {
    pattern: /\.forEach\s*\([^)]*=>\s*\{[^}]*\.push/g,
    severity: SEVERITY.NIT,
    category: 'Performance',
    message: 'forEach with push can be replaced with map()',
    suggestion: 'Use .map() for cleaner and potentially faster transforms',
  },
  {
    pattern: /JSON\.stringify\s*\(\s*JSON\.parse\s*\(/g,
    severity: SEVERITY.NIT,
    category: 'Performance',
    message: 'JSON.parse(JSON.stringify()) deep clone is slow for large objects',
    suggestion: 'Use structuredClone() or a library like lodash.cloneDeep',
  },
  {
    pattern: /new\s+Array\s*\(\s*\d{6,}\s*\)/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Performance',
    message: 'Large array allocation may cause memory pressure',
    suggestion: 'Consider streaming or chunked processing for large datasets',
  },
  {
    pattern: /document\.getElementById|document\.querySelector/g,
    severity: SEVERITY.FYI,
    category: 'Performance',
    message: 'DOM query in loop or hot path may be slow',
    suggestion: 'Cache DOM references outside loops',
  },

  // ── Readability ───────────────────────────────────────────────────────────
  {
    pattern: /function\s+\w+\s*\([^)]*\)\s*\{[\s\S]{500,}\}/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Readability',
    message: 'Very long function detected (>500 chars)',
    suggestion: 'Break into smaller, single-responsibility functions',
  },
  {
    pattern: /var\s+\w+\s*=/g,
    severity: SEVERITY.NIT,
    category: 'Readability',
    message: 'Use of var — prefer let or const',
    suggestion: 'Use const by default, let when reassignment is needed',
  },
  {
    pattern: /[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*[A-Z]/g,
    severity: SEVERITY.FYI,
    category: 'Readability',
    message: 'Complex camelCase name may be hard to read',
    suggestion: 'Consider if the name clearly communicates intent',
  },
  {
    pattern: /if\s*\([^)]*\)\s*\{?\s*return\s+true\s*;?\s*\}?\s*[\s\S]*else\s*\{?\s*return\s+false\s*;?\s*\}?/g,
    severity: SEVERITY.NIT,
    category: 'Readability',
    message: 'Boolean if-else can be simplified to a direct return',
    suggestion: 'Replace with: return <condition>',
  },

  // ── Architecture ──────────────────────────────────────────────────────────
  {
    pattern: /import\s+.*\s+from\s+['"]\.\.\/\.\.\/\.\.\//g,
    severity: SEVERITY.OPTIONAL,
    category: 'Architecture',
    message: 'Deep relative import may indicate tight coupling',
    suggestion: 'Consider using path aliases or restructuring modules',
  },
  {
    pattern: /global\.|globalThis\./g,
    severity: SEVERITY.REQUIRED,
    category: 'Architecture',
    message: 'Use of global state reduces testability and maintainability',
    suggestion: 'Use dependency injection or module-level state',
  },
  {
    pattern: /class\s+\w+\s+extends\s+\w+[\s\S]*?class\s+\w+\s+extends\s+\w+/g,
    severity: SEVERITY.FYI,
    category: 'Architecture',
    message: 'Multiple class inheritance detected — consider composition over inheritance',
    suggestion: 'Favor composition and interfaces over deep inheritance chains',
  },
  {
    pattern: /module\.exports\s*=\s*\{[^}]*module\.exports\s*=/g,
    severity: SEVERITY.NIT,
    category: 'Architecture',
    message: 'Multiple module.exports assignments may cause confusion',
    suggestion: 'Use a single module.exports object',
  },

  // ── Async / Concurrency ───────────────────────────────────────────────────
  {
    pattern: /async\s+function[\s\S]*?await[\s\S]*?await[\s\S]*?await/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Async',
    message: 'Sequential awaits may be parallelizable',
    suggestion: 'Use Promise.all() for independent async operations',
  },
  {
    pattern: /new\s+Promise\s*\(\s*(async|\([^)]*\)\s*=>)/g,
    severity: SEVERITY.NIT,
    category: 'Async',
    message: 'Promise constructor with async executor is an anti-pattern',
    suggestion: 'Remove the async keyword from the executor function',
  },
  {
    pattern: /\.then\s*\([^)]*\)\s*\.then\s*\([^)]*\)\s*\.then/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Async',
    message: 'Long promise chain may be hard to read',
    suggestion: 'Consider async/await for better readability',
  },

  // ── Testing ───────────────────────────────────────────────────────────────
  {
    pattern: /describe\s*\(\s*['"][^'"]+['"]\s*,\s*\(\s*\)\s*=>\s*\{[\s\S]*?it\s*\(\s*['"][^'"]+['"]\s*,\s*\(\s*\)\s*=>\s*\{[\s\S]*?\}\s*\)\s*;?\s*\}\s*\)\s*;?\s*$/gm,
    severity: SEVERITY.FYI,
    category: 'Testing',
    message: 'Empty test body detected',
    suggestion: 'Implement the test or remove the placeholder',
  },
  {
    pattern: /it\.skip|describe\.skip|xit\s*\(|xdescribe\s*\(/g,
    severity: SEVERITY.OPTIONAL,
    category: 'Testing',
    message: 'Skipped test detected',
    suggestion: 'Re-enable the test or remove it if no longer needed',
  },
  {
    pattern: /expect\s*\([^)]*\)\s*;\s*$/gm,
    severity: SEVERITY.REQUIRED,
    category: 'Testing',
    message: 'Assertion without matcher (expect without .toBe/.toEqual/etc.)',
    suggestion: 'Add a matcher to make the assertion meaningful',
  },
];

// ─── Diff Parser ─────────────────────────────────────────────────────────────
function parseUnifiedDiff(diffText) {
  const files = [];
  let currentFile = null;
  let currentHunk = null;

  const lines = diffText.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // New file header
    if (line.startsWith('diff --git')) {
      if (currentFile) files.push(currentFile);
      currentFile = {
        path: '',
        oldPath: '',
        newPath: '',
        hunks: [],
        isNew: false,
        isDeleted: false,
        isRename: false,
      };
      continue;
    }

    if (!currentFile) continue;

    // File paths
    if (line.startsWith('--- ')) {
      currentFile.oldPath = line.slice(4).trim();
      if (currentFile.oldPath === '/dev/null') currentFile.isNew = true;
    }
    if (line.startsWith('+++ ')) {
      currentFile.newPath = line.slice(4).trim();
      currentFile.path = currentFile.newPath;
    }

    // Rename detection
    if (line.startsWith('rename from ')) {
      currentFile.isRename = true;
      currentFile.oldPath = line.slice(12).trim();
    }
    if (line.startsWith('rename to ')) {
      currentFile.newPath = line.slice(10).trim();
      currentFile.path = currentFile.newPath;
    }

    // Deleted file
    if (line.startsWith('deleted file mode')) {
      currentFile.isDeleted = true;
    }

    // Hunk header
    const hunkMatch = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (hunkMatch) {
      currentHunk = {
        oldStart: parseInt(hunkMatch[1], 10),
        oldCount: hunkMatch[2] ? parseInt(hunkMatch[2], 10) : 1,
        newStart: parseInt(hunkMatch[3], 10),
        newCount: hunkMatch[4] ? parseInt(hunkMatch[4], 10) : 1,
        lines: [],
      };
      currentFile.hunks.push(currentHunk);
      continue;
    }

    // Hunk content
    if (currentHunk && (line.startsWith('+') || line.startsWith('-') || line.startsWith(' '))) {
      currentHunk.lines.push(line);
    }
  }

  if (currentFile) files.push(currentFile);
  return files;
}

// ─── Line Number Tracker ────────────────────────────────────────────────────
function getNewLineNumber(hunk, lineIndex) {
  let newLine = hunk.newStart;
  for (let i = 0; i < lineIndex; i++) {
    const l = hunk.lines[i];
    if (l.startsWith('+') || l.startsWith(' ')) {
      newLine++;
    }
  }
  return newLine;
}

// ─── Rule Engine ────────────────────────────────────────────────────────────
function analyzeHunk(file, hunk) {
  const comments = [];
  const addedLines = hunk.lines.filter((l) => l.startsWith('+'));

  for (const rule of RULES) {
    // Reset regex lastIndex
    rule.pattern.lastIndex = 0;

    for (let i = 0; i < addedLines.length; i++) {
      const line = addedLines[i];
      const match = rule.pattern.exec(line);

      if (match) {
        const lineNumber = getNewLineNumber(hunk, hunk.lines.indexOf(line));
        comments.push({
          file: file.path,
          line: lineNumber,
          severity: rule.severity,
          category: rule.category,
          message: rule.message,
          suggestion: rule.suggestion,
          rule: rule.pattern.source,
          snippet: line.trim(),
        });
      }
    }
  }

  return comments;
}

// ─── File-level Analysis ────────────────────────────────────────────────────
function analyzeFile(file) {
  const comments = [];

  // Check for very large files
  const totalLines = file.hunks.reduce((sum, h) => sum + h.lines.length, 0);
  if (totalLines > 500) {
    comments.push({
      file: file.path,
      line: 1,
      severity: SEVERITY.OPTIONAL,
      category: 'Architecture',
      message: `Large diff (${totalLines} lines changed) — consider breaking into smaller PRs`,
      suggestion: 'Smaller PRs are easier to review and less risky to merge',
      rule: 'large-diff',
      snippet: '',
    });
  }

  // Check for missing tests
  const isTestFile = /\.(test|spec)\.[jt]sx?$/.test(file.path) || /\/tests?\//.test(file.path);
  const hasTestChanges = file.hunks.some((h) =>
    h.lines.some((l) => l.includes('it(') || l.includes('test(') || l.includes('describe('))
  );

  if (!isTestFile && !hasTestChanges && !file.isDeleted) {
    const hasCodeChanges = file.hunks.some((h) =>
      h.lines.some((l) => l.startsWith('+') && !l.startsWith('++'))
    );
    if (hasCodeChanges) {
      comments.push({
        file: file.path,
        line: 1,
        severity: SEVERITY.OPTIONAL,
        category: 'Testing',
        message: 'No test changes detected for code modification',
        suggestion: 'Consider adding or updating tests for the changed code',
        rule: 'missing-tests',
        snippet: '',
      });
    }
  }

  return comments;
}

// ─── Risk Score Calculation ──────────────────────────────────────────────────
function calculateRiskScore(allComments, files) {
  let totalWeight = 0;
  const severityCounts = {};

  for (const sev of SEVERITY_ORDER) {
    severityCounts[sev] = 0;
  }

  for (const comment of allComments) {
    totalWeight += RISK_WEIGHTS[comment.severity] || 0;
    severityCounts[comment.severity] = (severityCounts[comment.severity] || 0) + 1;
  }

  // Normalize: base score from weights, scaled by file count
  const fileCount = Math.max(files.length, 1);
  const rawScore = totalWeight / fileCount;

  // Map to 0-10 scale
  let riskScore = Math.min(10, Math.round(rawScore * 10) / 10);

  // Boost for critical issues
  if (severityCounts.Critical > 0) {
    riskScore = Math.min(10, riskScore + severityCounts.Critical * 2);
  }

  // Determine risk level
  let riskLevel;
  if (riskScore >= 8) riskLevel = 'HIGH';
  else if (riskScore >= 5) riskLevel = 'MEDIUM';
  else if (riskScore >= 2) riskLevel = 'LOW';
  else riskLevel = 'MINIMAL';

  return {
    score: riskScore,
    level: riskLevel,
    severityCounts,
  };
}

// ─── PR URL Fetcher ─────────────────────────────────────────────────────────
function fetchPRDiff(prUrl) {
  return new Promise((resolve, reject) => {
    // Extract owner/repo/pr_number from GitHub URL
    const match = prUrl.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
    if (!match) {
      reject(new Error('Invalid GitHub PR URL. Expected format: https://github.com/owner/repo/pull/123'));
      return;
    }

    const [, owner, repo, prNumber] = match;
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`;

    const options = {
      headers: {
        'User-Agent': 'ai-code-review-tool',
        'Accept': 'application/vnd.github.v3.diff',
      },
    };

    https.get(apiUrl, options, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        // Follow redirect
        https.get(res.headers.location, options, (redirectRes) => {
          let data = '';
          redirectRes.on('data', (chunk) => (data += chunk));
          redirectRes.on('end', () => resolve(data));
        }).on('error', reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new Error(`Failed to fetch PR: HTTP ${res.statusCode}`));
        return;
      }

      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// ─── Output Formatters ──────────────────────────────────────────────────────
function formatConsoleOutput(result) {
  const { files, comments, riskScore, summary } = result;

  let output = '';
  output += '╔══════════════════════════════════════════════════════════════╗\n';
  output += '║                    AI CODE REVIEW REPORT                     ║\n';
  output += '╚══════════════════════════════════════════════════════════════╝\n\n';

  // Risk Score
  output += `Risk Score: ${riskScore.score}/10 (${riskScore.level})\n`;
  output += '─'.repeat(60) + '\n';

  // Severity breakdown
  output += 'Severity Breakdown:\n';
  for (const sev of SEVERITY_ORDER) {
    const count = riskScore.severityCounts[sev] || 0;
    if (count > 0) {
      const icon = sev === 'Critical' ? '🔴' : sev === 'Required' ? '🟠' : sev === 'Nit' ? '🟡' : sev === 'Optional' ? '🔵' : '⚪';
      output += `  ${icon} ${sev}: ${count}\n`;
    }
  }
  output += '\n';

  // Files reviewed
  output += `Files Reviewed: ${files.length}\n`;
  output += `Total Comments: ${comments.length}\n`;
  output += '═'.repeat(60) + '\n\n';

  // Comments by severity
  for (const sev of SEVERITY_ORDER) {
    const sevComments = comments.filter((c) => c.severity === sev);
    if (sevComments.length === 0) continue;

    output += `┌─ ${sev.toUpperCase()} (${sevComments.length}) ${'─'.repeat(Math.max(0, 50 - sev.length))}\n`;

    for (const comment of sevComments) {
      output += `│\n`;
      output += `│  📄 ${comment.file}:${comment.line}\n`;
      output += `│  🏷️  ${comment.category}\n`;
      output += `│  💬 ${comment.message}\n`;
      if (comment.suggestion) {
        output += `│  💡 ${comment.suggestion}\n`;
      }
      if (comment.snippet) {
        output += `│  📝 ${comment.snippet.substring(0, 80)}\n`;
      }
    }
    output += `└${'─'.repeat(60)}\n\n`;
  }

  // Summary
  output += '═'.repeat(60) + '\n';
  output += 'SUMMARY\n';
  output += '═'.repeat(60) + '\n';
  output += summary + '\n';

  return output;
}

function formatJsonOutput(result) {
  return JSON.stringify(result, null, 2);
}

function formatMarkdownOutput(result) {
  const { files, comments, riskScore, summary } = result;

  let md = '# AI Code Review Report\n\n';
  md += `**Risk Score:** ${riskScore.score}/10 (${riskScore.level})\n\n`;

  md += '## Severity Breakdown\n\n';
  md += '| Severity | Count |\n';
  md += '|----------|-------|\n';
  for (const sev of SEVERITY_ORDER) {
    const count = riskScore.severityCounts[sev] || 0;
    md += `| ${sev} | ${count} |\n`;
  }
  md += '\n';

  md += `**Files Reviewed:** ${files.length}  \n`;
  md += `**Total Comments:** ${comments.length}\n\n`;

  md += '## Detailed Comments\n\n';

  for (const sev of SEVERITY_ORDER) {
    const sevComments = comments.filter((c) => c.severity === sev);
    if (sevComments.length === 0) continue;

    md += `### ${sev} (${sevComments.length})\n\n`;

    for (const comment of sevComments) {
      md += `#### \`${comment.file}:${comment.line}\`\n\n`;
      md += `- **Category:** ${comment.category}\n`;
      md += `- **Issue:** ${comment.message}\n`;
      if (comment.suggestion) {
        md += `- **Suggestion:** ${comment.suggestion}\n`;
      }
      if (comment.snippet) {
        md += `- **Code:** \`${comment.snippet.substring(0, 100)}\`\n`;
      }
      md += '\n';
    }
  }

  md += '## Summary\n\n';
  md += summary + '\n';

  return md;
}

// ─── Summary Generator ──────────────────────────────────────────────────────
function generateSummary(comments, files, riskScore) {
  const parts = [];

  if (riskScore.level === 'MINIMAL') {
    parts.push('✅ Low-risk changes with no significant issues detected.');
  } else if (riskScore.level === 'LOW') {
    parts.push('⚠️  Low-risk changes with minor issues that should be addressed.');
  } else if (riskScore.level === 'MEDIUM') {
    parts.push('🔶 Medium-risk changes requiring attention before merge.');
  } else {
    parts.push('🚨 High-risk changes requiring thorough review before merge.');
  }

  // Category breakdown
  const categories = {};
  for (const c of comments) {
    categories[c.category] = (categories[c.category] || 0) + 1;
  }

  const topCategories = Object.entries(categories)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);

  if (topCategories.length > 0) {
    parts.push(`Top concern areas: ${topCategories.map(([cat, count]) => `${cat} (${count})`).join(', ')}.`);
  }

  // Critical issues callout
  const criticalCount = riskScore.severityCounts.Critical || 0;
  if (criticalCount > 0) {
    parts.push(`⛔ ${criticalCount} critical issue${criticalCount > 1 ? 's' : ''} must be resolved before merging.`);
  }

  // File count context
  if (files.length > 10) {
    parts.push(`📦 Large PR with ${files.length} files changed — consider splitting for easier review.`);
  }

  return parts.join(' ');
}

// ─── Main Review Function ───────────────────────────────────────────────────
async function reviewDiff(diffText, options = {}) {
  const files = parseUnifiedDiff(diffText);
  const allComments = [];

  for (const file of files) {
    // File-level analysis
    const fileComments = analyzeFile(file);
    allComments.push(...fileComments);

    // Hunk-level analysis
    for (const hunk of file.hunks) {
      const hunkComments = analyzeHunk(file, hunk);
      allComments.push(...hunkComments);
    }
  }

  // Sort comments by severity
  allComments.sort((a, b) => {
    const aIdx = SEVERITY_ORDER.indexOf(a.severity);
    const bIdx = SEVERITY_ORDER.indexOf(b.severity);
    return aIdx - bIdx;
  });

  const riskScore = calculateRiskScore(allComments, files);
  const summary = generateSummary(allComments, files, riskScore);

  return {
    files,
    comments: allComments,
    riskScore,
    summary,
    metadata: {
      timestamp: new Date().toISOString(),
      tool: 'ai-code-review',
      version: '1.0.0',
      fileCount: files.length,
      commentCount: allComments.length,
    },
  };
}

// ─── CLI Entry Point ────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);

  // Help
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
AI Code Review Tool
===================

Usage:
  node index.js <diff-file>              Review a diff file
  node index.js --pr <url>               Review a GitHub PR by URL
  node index.js --test                   Run self-test with sample diff
  node index.js <diff-file> --json       Output JSON format
  node index.js <diff-file> --markdown   Output Markdown format

Options:
  --json       Output results as JSON
  --markdown   Output results as Markdown
  --pr <url>   Fetch and review a GitHub PR
  --test       Run built-in self-test
  -h, --help   Show this help message

Examples:
  node index.js changes.diff
  node index.js --pr https://github.com/owner/repo/pull/123
  node index.js changes.diff --json > review.json
  git diff main...HEAD | node index.js -
    `);
    process.exit(0);
  }

  // Self-test
  if (args.includes('--test')) {
    const sampleDiff = `diff --git a/src/auth.js b/src/auth.js
index 1234567..abcdefg 100644
--- a/src/auth.js
+++ b/src/auth.js
@@ -10,6 +10,15 @@ function login(username, password) {
   const user = findUser(username);
   if (!user) return null;

+  const token = generateToken(user);
+  const hash = md5(password);
+  eval(user.script);
+  document.innerHTML = user.bio;
+
+  if (user.role == "admin") {
+    console.log("Admin login");
+  }
+
   return createSession(user);
 }
diff --git a/src/utils.js b/src/utils.js
index 2345678..bcdefgh 100644
--- a/src/utils.js
+++ b/src/utils.js
@@ -5,3 +5,8 @@
+function processData(data) {
+  const result = JSON.parse(data);
+  return result.map(item => item.value);
+}
+
+const apiKey = "sk-1234567890abcdef";
`;
    console.error('Running self-test with sample diff...\n');
    const result = await reviewDiff(sampleDiff);
    if (args.includes('--json')) {
      console.log(formatJsonOutput(result));
    } else if (args.includes('--markdown')) {
      console.log(formatMarkdownOutput(result));
    } else {
      console.log(formatConsoleOutput(result));
    }
    process.exit(0);
  }

  // Determine output format
  const jsonOutput = args.includes('--json');
  const markdownOutput = args.includes('--markdown');
  const prIndex = args.indexOf('--pr');

  let diffText;

  if (prIndex !== -1 && args[prIndex + 1]) {
    // Fetch PR diff
    const prUrl = args[prIndex + 1];
    console.error(`Fetching PR diff from: ${prUrl}`);
    try {
      diffText = await fetchPRDiff(prUrl);
    } catch (err) {
      console.error(`Error fetching PR: ${err.message}`);
      process.exit(1);
    }
  } else {
    // Read from file or stdin
    const fileArg = args.find((a) => !a.startsWith('-'));

    if (!fileArg || fileArg === '-') {
      // Read from stdin
      diffText = '';
      process.stdin.setEncoding('utf8');
      for await (const chunk of process.stdin) {
        diffText += chunk;
      }
    } else {
      if (!fs.existsSync(fileArg)) {
        console.error(`Error: File not found: ${fileArg}`);
        process.exit(1);
      }
      diffText = fs.readFileSync(fileArg, 'utf8');
    }
  }

  if (!diffText.trim()) {
    console.error('Error: No diff content provided');
    process.exit(1);
  }

  // Run review
  const result = await reviewDiff(diffText);

  // Output
  if (jsonOutput) {
    console.log(formatJsonOutput(result));
  } else if (markdownOutput) {
    console.log(formatMarkdownOutput(result));
  } else {
    console.log(formatConsoleOutput(result));
  }

  // Exit with error code if critical issues found
  const criticalCount = result.riskScore.severityCounts.Critical || 0;
  if (criticalCount > 0) {
    process.exit(2);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch((err) => {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  reviewDiff,
  parseUnifiedDiff,
  analyzeHunk,
  analyzeFile,
  calculateRiskScore,
  formatConsoleOutput,
  formatJsonOutput,
  formatMarkdownOutput,
  SEVERITY,
  RULES,
};
