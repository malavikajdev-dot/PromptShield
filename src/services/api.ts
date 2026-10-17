/**
 * PromptShield API Client Service
 * Communicates strictly with the server-side Express backend.
 */

import {
  AuditEvent,
  AuditIntegrityReport,
  AutomatedTestCase,
  ComparisonResult,
  PlaygroundTestResult,
  SecurityPolicy,
  SystemHealthStatus,
} from '../types/security.ts';

export async function fetchHealth(): Promise<SystemHealthStatus> {
  const res = await fetch('/api/health');
  if (!res.ok) throw new Error('Failed to fetch system health status');
  return res.json();
}

export async function fetchPolicy(): Promise<SecurityPolicy> {
  const res = await fetch('/api/policy');
  if (!res.ok) throw new Error('Failed to fetch security policy');
  return res.json();
}

export async function savePolicy(policy: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
  const res = await fetch('/api/policy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update security policy');
  }
  return res.json();
}

export async function resetPolicy(): Promise<{ message: string; policy: SecurityPolicy }> {
  const res = await fetch('/api/policy/reset', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reset security policy');
  return res.json();
}

export async function runPlaygroundTest(params: {
  prompt: string;
  scenarioTitle?: string;
  scenarioKey?: string;
  forceFallback?: boolean;
}): Promise<PlaygroundTestResult> {
  const res = await fetch('/api/test/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to analyze test prompt');
  }
  return res.json();
}

export async function runComparison(params: {
  prompt: string;
  scenarioTitle?: string;
}): Promise<ComparisonResult> {
  const res = await fetch('/api/test/compare', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to run security comparison');
  }
  return res.json();
}

export async function fetchAuditLogs(): Promise<AuditEvent[]> {
  const res = await fetch('/api/audit/logs');
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  return res.json();
}

export async function verifyAuditIntegrity(): Promise<AuditIntegrityReport> {
  const res = await fetch('/api/audit/verify');
  if (!res.ok) throw new Error('Failed to verify audit ledger integrity');
  return res.json();
}

export async function simulateAuditTamper(recordId?: string): Promise<any> {
  const res = await fetch('/api/audit/tamper', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recordId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to simulate audit tampering');
  }
  return res.json();
}

export async function restoreAuditChain(): Promise<any> {
  const res = await fetch('/api/audit/restore', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to restore audit chain');
  return res.json();
}

export async function approveAuditEvent(auditId: string): Promise<any> {
  const res = await fetch('/api/audit/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ auditId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to approve action');
  }
  return res.json();
}

export async function fetchTestSuite(): Promise<AutomatedTestCase[]> {
  const res = await fetch('/api/test-suite');
  if (!res.ok) throw new Error('Failed to fetch test suite definitions');
  return res.json();
}

export async function runTestSuite(): Promise<{
  total: number;
  passed: number;
  failed: number;
  passRatePercent: number;
  executedAt: string;
  tests: AutomatedTestCase[];
}> {
  const res = await fetch('/api/test-suite/run', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to execute automated test suite');
  return res.json();
}

export async function fetchArmorIQStatus(): Promise<any> {
  const res = await fetch('/api/armoriq/status');
  if (!res.ok) throw new Error('Failed to fetch ArmorIQ status');
  return res.json();
}
