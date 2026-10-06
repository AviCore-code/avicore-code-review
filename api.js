#!/usr/bin/env node
'use strict';

const http = require('http');
const { reviewDiff } = require('./index.js');

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || 'dev-key';

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const path = url.pathname;
  const method = req.method?.toUpperCase() || 'GET';

  // Health check
  if (path === '/health' && method === 'GET') {
    return json(res, 200, { ok: true, service: 'avicore-code-review', version: '1.0.0' });
  }

  // Review endpoint
  if (path === '/review' && method === 'POST') {
    const auth = req.headers['authorization'];
    if (auth !== `Bearer ${API_KEY}`) {
      return json(res, 401, { error: 'Unauthorized' });
    }

    const body = await readBody(req);
    let diff;
    try {
      const parsed = JSON.parse(body);
      diff = parsed.diff;
    } catch {
      diff = body;
    }

    if (!diff || typeof diff !== 'string') {
      return json(res, 400, { error: 'diff is required' });
    }

    try {
      const result = await reviewDiff(diff);
      return json(res, 200, result);
    } catch (error) {
      return json(res, 500, { error: error.message });
    }
  }

  // Batch review
  if (path === '/review/batch' && method === 'POST') {
    const auth = req.headers['authorization'];
    if (auth !== `Bearer ${API_KEY}`) {
      return json(res, 401, { error: 'Unauthorized' });
    }

    const body = await readBody(req);
    let diffs;
    try {
      const parsed = JSON.parse(body);
      diffs = parsed.diffs;
    } catch {
      return json(res, 400, { error: 'Invalid JSON' });
    }

    if (!Array.isArray(diffs) || diffs.length === 0) {
      return json(res, 400, { error: 'diffs array is required' });
    }

    const results = [];
    for (const diff of diffs) {
      try {
        const result = await reviewDiff(diff);
        results.push({ ok: true, result });
      } catch (error) {
        results.push({ ok: false, error: error.message });
      }
    }

    return json(res, 200, { results });
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[avicore-code-review] API listening on 127.0.0.1:${PORT}`);
});
