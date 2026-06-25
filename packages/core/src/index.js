// ============================================================
// @anti-scam/core — Shared pure logic entry point
// Can be imported by:
//   - React Native (import { computeScore } from '@anti-scam/core')
//   - Node.js backend (const { computeScore } = require('@anti-scam/core'))
//   - Extension (via heuristic.js wrapper for importScripts compat)
// ============================================================

// Constants & data
export * from './constants.js';

// URL utilities
export * from './url.js';

// Brand detection
export * from './brand.js';

// URL analysis (findings, redirect, trust context)
export * from './analyze-url.js';

// Scoring engine
export * from './compute-score.js';

// HTML signal parser (pure, no DOM)
export * from './signals.js';

// DOM features collector (pure, no Chrome APIs)
export * from './features.js';