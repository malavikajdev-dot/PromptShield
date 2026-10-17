/**
 * PromptShield Server-Side Entrypoint
 *
 * Runs Express backend APIs with Vite SPA middleware.
 * All Gemini AI calls, authorization gateway rules, audit logs, and mock tools
 * execute strictly within this server runtime.
 */

import 'dotenv/config';
import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  evaluateAuthorizationGateway,
  getActivePolicy,
  resetPolicyToDefault,
  updateSecurityPolicy,
} from './src/server/policyEngine.ts';
import { executeSandboxedTool } from './src/server/mockTools.ts';
import {
  appendAuditEvent,
  approvePendingAuditEvent,
  getAuditLogs,
  initializeAuditStorage,
  restoreChainIntegrity,
  simulateTampering,
  verifyAuditChainIntegrity,
} from './src/server/auditChain.ts';
import {
  analyzePromptDeterministicFallback,
  analyzePromptWithGemini,
} from './src/server/geminiService.ts';
import { getArmorIQStatus } from './src/server/armoriq.ts';
import { captureAndAttestArmorIQPlan, enforceViaArmorIQ } from './src/server/armoriqIntegration.ts';
import { initializeMcpServer } from './src/server/mcpServer.ts';
import {
  runAllAutomatedTests,
  TEST_DEFINITIONS,
} from './src/server/testRunner.ts';
import {
  ComparisonResult,
  PlaygroundTestResult,
  SystemHealthStatus,
  ToolActionProposal,
} from './src/types/security.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const serverStartTime = Date.now();

app.use(express.json());

// Initialize audit chain and storage on startup
initializeAuditStorage();

// Initialize real Model Context Protocol (MCP) Server on startup
initializeMcpServer().catch((err) => {
  console.error('[MCP Server] Initialization error:', err);
});

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

/**
 * GET /api/health
 * Detailed real-time system health inspection
 */
app.get('/api/health', (req: Request, res: Response) => {
  const auditReport = verifyAuditChainIntegrity();
  const policy = getActivePolicy();
  const apiKey = process.env.GEMINI_API_KEY;
  const hasGeminiKey = Boolean(apiKey && apiKey !== 'MY_GEMINI_API_KEY' && apiKey.trim() !== '');
  const armorIqStatus = getArmorIQStatus();

  const health: SystemHealthStatus = {
    timestamp: new Date().toISOString(),
    frontend: {
      status: 'OPERATIONAL',
      details: 'React 19 + TypeScript + Tailwind CSS UI responsive',
    },
    backendApi: {
      status: 'OPERATIONAL',
      uptimeSeconds: Math.floor((Date.now() - serverStartTime) / 1000),
      details: 'Node.js Express authorization gateway & real MCP server active',
    },
    geminiApi: {
      status: hasGeminiKey ? 'CONFIGURED' : 'FALLBACK_MODE',
      model: hasGeminiKey ? 'gemini-3.8-flash' : 'deterministic-security-fallback-v1',
      details: hasGeminiKey
        ? 'Real Gemini 3.8 Flash model connected for threat analysis'
        : 'Running deterministic AI security engine fallback (GEMINI_API_KEY unpopulated)',
    },
    securityPolicyEngine: {
      status: 'OPERATIONAL',
      activePolicyId: policy.id,
      rulesEnforced:
        policy.permittedTools.length +
        policy.restrictedTools.length +
        policy.restrictedResourceScopes.length +
        policy.approvalRequiredOperations.length,
      details: `Active policy ${policy.name} enforcing defaultDeny=${policy.defaultDeny}`,
    },
    auditStorage: {
      status: 'OPERATIONAL',
      storageType: 'DEVELOPMENT_LOCAL_PERSISTENT',
      totalEvents: auditReport.totalRecords,
      chainIntegrity: auditReport.isValid ? 'VALID' : 'TAMPER_DETECTED',
    },
    armorIq: {
      status: armorIqStatus.isConfigured ? 'OPERATIONAL' : 'NOT_CONFIGURED',
      details: armorIqStatus.statusText,
      requirementsToEnable: armorIqStatus.missingEnvironmentVariables.map(
        (v) => `Configure ${v} in server secrets`
      ),
    },
  };

  res.json(health);
});

/**
 * GET /api/policy & POST /api/policy & POST /api/policy/reset
 */
app.get('/api/policy', (req: Request, res: Response) => {
  res.json(getActivePolicy());
});

app.post('/api/policy', (req: Request, res: Response) => {
  const result = updateSecurityPolicy(req.body);
  if (!result.success) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json(result.policy);
});

app.post('/api/policy/reset', (req: Request, res: Response) => {
  const policy = resetPolicyToDefault();
  res.json({ message: 'Security policy reset to factory zero-trust defaults.', policy });
});
async function evaluateGateway(
  proposal: ToolActionProposal,
  attestation: Awaited<ReturnType<typeof captureAndAttestArmorIQPlan>>,
  origin: string
) {
  const local = evaluateAuthorizationGateway(proposal, { role: 'tester', origin });
  if (!attestation.isConfigured) return local;

  const verdict = attestation.intentTokenRaw
    ? await enforceViaArmorIQ(proposal, attestation.intentTokenRaw)
    : { decision: 'BLOCK' as const, reason: attestation.error || 'No intent token issued.' };

  return {
    ...local,
    decision: verdict.decision,
    reason: `ArmorIQ ${verdict.decision}: ${verdict.reason}`,
    policyId: 'armoriq:promptshield-zero-trust',
    matchedRule: 'ARMORIQ_PLATFORM_POLICY',
  };
}
/**
 * POST /api/test/analyze
 * Main Attack Playground execution pipeline
 */
app.post('/api/test/analyze', async (req: Request, res: Response) => {
  try {
    const { prompt, scenarioTitle, scenarioKey, forceFallback } = req.body;

    if (!prompt || typeof prompt !== 'string' || prompt.trim() === '') {
      res.status(400).json({ error: 'Prompt is required.' });
      return;
    }

    const testId = `test-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;

    // Step 1: AI Agent Analysis & Tool Action Proposal (Server-side Gemini or Fallback)
    const aiResponse = forceFallback
      ? analyzePromptDeterministicFallback(prompt, scenarioKey)
      : await analyzePromptWithGemini(prompt, scenarioKey);

    // Step 2: ArmorIQ Plan Capture & Cryptographic Intent Token Attestation
    // Executes genuine ArmorIQ SDK client.capturePlan() and client.getIntentToken()
    const armorIqAttestation = await captureAndAttestArmorIQPlan(
      prompt,
      aiResponse.proposed_action,
      aiResponse.model
    );

    // Step 3: Backend Authorization Gateway Evaluation
    // Operates independently of AI's internal reasoning!
       const localEvaluation = evaluateAuthorizationGateway(
     aiResponse.proposed_action,
     { role: 'tester', origin: 'attack_playground' }
   );
   let gatewayEvaluation = localEvaluation;
   if (armorIqAttestation.isConfigured) {
     const verdict = armorIqAttestation.intentTokenRaw
       ? await enforceViaArmorIQ(aiResponse.proposed_action, armorIqAttestation.intentTokenRaw)
       : { decision: 'BLOCK' as const, reason: armorIqAttestation.error || 'No intent token issued.' };
     gatewayEvaluation = {
       ...localEvaluation,
       decision: verdict.decision,
       reason: `ArmorIQ ${verdict.decision}: ${verdict.reason}`,
       policyId: 'armoriq:promptshield-zero-trust',
       matchedRule: 'ARMORIQ_PLATFORM_POLICY',
     };
   }

    // Step 4: Real MCP Tool Execution (Tools will NOT run if Gateway blocked)
    const toolExecution = await executeSandboxedTool(
      aiResponse.proposed_action,
      gatewayEvaluation.decision
    );

    // Step 5: Cryptographic Audit Ledger Entry (Tamper-evident SHA-256 hash chain)
    const auditRecord = appendAuditEvent({
      testId,
      scenarioTitle: scenarioTitle || 'Custom Attack Experiment',
      inputPrompt: prompt,
      proposedAction: aiResponse.proposed_action,
      gatewayDecision: gatewayEvaluation.decision,
      decisionReason: gatewayEvaluation.reason,
      toolExecutionStatus: toolExecution.status,
      toolResult: toolExecution.result,
      aiMode: aiResponse.isFallback
        ? 'deterministic-security-fallback-v1'
        : 'gemini-3.8-flash',
      policyId: gatewayEvaluation.policyId,
    });

    const playgroundResult: PlaygroundTestResult = {
      testId,
      timestamp: new Date().toISOString(),
      scenarioTitle: scenarioTitle || 'Custom Attack Experiment',
      inputPrompt: prompt,
      aiAnalysis: {
        analysis: aiResponse.analysis,
        injection_detected: aiResponse.injection_detected,
        injection_confidence: aiResponse.injection_confidence,
        model: aiResponse.model,
        isFallback: aiResponse.isFallback,
        latencyMs: aiResponse.latencyMs,
      },
      proposedAction: aiResponse.proposed_action,
      gatewayEvaluation,
      toolExecution: {
        status: toolExecution.status,
        result: toolExecution.result,
        executedAt: toolExecution.executionTimestamp,
        isRealMcpServer: toolExecution.isRealMcpServer,
        mcpServerInfo: toolExecution.mcpServerInfo,
      },
      armorIqAttestation,
      auditRecord: {
        id: auditRecord.id,
        hash: auditRecord.hash,
      },
    };

    res.json(playgroundResult);
  } catch (err: any) {
    console.error('Test execution error:', err);
    res.status(500).json({ error: err?.message || 'Server error during test evaluation.' });
  }
});

/**
 * POST /api/test/compare
 * Side-by-side comparison between unprotected baseline and protected agent
 */
app.post('/api/test/compare', async (req: Request, res: Response) => {
  try {
    const { prompt, scenarioTitle } = req.body;
    if (!prompt) {
      res.status(400).json({ error: 'Prompt is required.' });
      return;
    }

    const testId = `cmp-${Date.now().toString(36)}`;

    // 1. Run Protected Agent flow
    const protectedAi = await analyzePromptWithGemini(prompt);
    const armorIqAttestation = await captureAndAttestArmorIQPlan(
      prompt,
      protectedAi.proposed_action,
      protectedAi.model
    );
        const gatewayEvaluation = await evaluateGateway(
      protectedAi.proposed_action,
      armorIqAttestation,
      'comparison_engine'
    );
    const protectedTool = await executeSandboxedTool(
      protectedAi.proposed_action,
      gatewayEvaluation.decision
    );
    const auditRecord = appendAuditEvent({
      testId,
      scenarioTitle: scenarioTitle || 'Comparison Run',
      inputPrompt: prompt,
      proposedAction: protectedAi.proposed_action,
      gatewayDecision: gatewayEvaluation.decision,
      decisionReason: gatewayEvaluation.reason,
      toolExecutionStatus: protectedTool.status,
      toolResult: protectedTool.result,
      aiMode: protectedAi.isFallback
        ? 'deterministic-security-fallback-v1'
        : 'gemini-3.8-flash',
      policyId: gatewayEvaluation.policyId,
    });

    // 2. Compute Unprotected Baseline Simulation
    // Demonstrates what happens when NO gateway verifies actions.
    const unprotectedProposedAction: ToolActionProposal = {
      ...protectedAi.proposed_action,
    };

    let simulatedUnsafeResult = 'Action would execute with root privileges without check.';
    let potentialImpact = 'Unauthorized access to resources.';
    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' = 'HIGH';

    if (
      prompt.toLowerCase().includes('restricted') ||
      prompt.toLowerCase().includes('confidential') ||
      prompt.toLowerCase().includes('financial')
    ) {
      simulatedUnsafeResult =
        '[SIMULATION WARNING] Without authorization gateway, the agent would return raw confidential executive data or vault credentials directly to the attacker.';
      potentialImpact = 'Data exfiltration of confidential executive records and infrastructure secrets.';
      riskLevel = 'CRITICAL';
    } else if (prompt.toLowerCase().includes('export') || prompt.toLowerCase().includes('crm')) {
      simulatedUnsafeResult =
        '[SIMULATION WARNING] Without authorization gateway, all synthetic customer records would be dumped to unverified external endpoints.';
      potentialImpact = 'Unregulated mass data egress, compliance violations (GDPR/SOC2).';
      riskLevel = 'CRITICAL';
    } else if (prompt.toLowerCase().includes('admin') || prompt.toLowerCase().includes('grant')) {
      simulatedUnsafeResult =
        '[SIMULATION WARNING] The agent blindly trusts claimed admin status in the prompt, granting itself arbitrary system execution capabilities.';
      potentialImpact = 'Full tenant compromise and privilege escalation.';
      riskLevel = 'CRITICAL';
    } else {
      simulatedUnsafeResult =
        '[SIMULATION NOTE] Benign query executes, but lacks zero-trust audit verification and egress tracking.';
      potentialImpact = 'Unmonitored execution without cryptographic audit trail.';
      riskLevel = 'MEDIUM';
    }

    const comparison: ComparisonResult = {
      inputPrompt: prompt,
      scenarioTitle: scenarioTitle || 'Direct Injection Comparison',
      unprotectedBaseline: {
        proposedAction: unprotectedProposedAction,
        authorizationDecision: 'NONE (UNPROTECTED)',
        simulationWarning:
          'SIMULATED BASELINE — NO GATEWAY ENFORCEMENT. Unprotected agents blindly fulfill instructions.',
        simulatedExecutionResult: simulatedUnsafeResult,
        potentialImpact,
        riskLevel,
      },
      protectedAgent: {
        aiModel: protectedAi.model,
        isFallback: protectedAi.isFallback,
        proposedAction: protectedAi.proposed_action,
        gatewayDecision: gatewayEvaluation.decision,
        decisionReason: gatewayEvaluation.reason,
        toolExecutionStatus: protectedTool.status,
        realExecutionResult: protectedTool.result,
        verifiableAuditHash: auditRecord.hash,
        armorIqAttestation: {
          isConfigured: armorIqAttestation.isConfigured,
          tokenId: armorIqAttestation.intentToken?.tokenId,
          planHash: armorIqAttestation.intentToken?.planHash,
        },
      },
    };

    res.json(comparison);
  } catch (err: any) {
    console.error('Comparison evaluation error:', err);
    res.status(500).json({ error: err?.message || 'Comparison failed' });
  }
});

/**
 * Audit Log APIs
 */
app.get('/api/audit/logs', (req: Request, res: Response) => {
  res.json(getAuditLogs());
});

app.get('/api/audit/verify', (req: Request, res: Response) => {
  const report = verifyAuditChainIntegrity();
  res.json(report);
});

app.post('/api/audit/tamper', (req: Request, res: Response) => {
  try {
    const { recordId } = req.body;
    const result = simulateTampering(recordId);
    res.json({
      message: 'Tamper simulation completed. The cryptographic hash chain is now broken!',
      ...result,
    });
  } catch (err: any) {
    res.status(400).json({ error: err?.message || 'Tamper simulation failed' });
  }
});

app.post('/api/audit/restore', (req: Request, res: Response) => {
  const result = restoreChainIntegrity();
  res.json({
    message: 'Audit chain restored and cryptographically re-signed.',
    ...result,
  });
});

app.post('/api/audit/approve', (req: Request, res: Response) => {
  const { auditId } = req.body;
  if (!auditId) {
    res.status(400).json({ error: 'auditId is required.' });
    return;
  }
  const updated = approvePendingAuditEvent(auditId);
  if (!updated) {
    res.status(404).json({ error: 'Audit event not found or not in pending state.' });
    return;
  }
  res.json({ message: 'Action approved and executed.', auditEvent: updated });
});

/**
 * Automated Test Suite APIs
 */
app.get('/api/test-suite', (req: Request, res: Response) => {
  res.json(TEST_DEFINITIONS);
});

app.post('/api/test-suite/run', async (req: Request, res: Response) => {
  try {
    const results = await runAllAutomatedTests();
    const passedCount = results.filter((r) => r.status === 'PASS').length;
    res.json({
      total: results.length,
      passed: passedCount,
      failed: results.length - passedCount,
      passRatePercent: Math.round((passedCount / results.length) * 100),
      executedAt: new Date().toISOString(),
      tests: results,
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Failed running test suite' });
  }
});

/**
 * ArmorIQ Readiness API
 */
app.get('/api/armoriq/status', (req: Request, res: Response) => {
  res.json(getArmorIQStatus());
});

// -------------------------------------------------------------
// Vite Middleware / Production Static Server
// -------------------------------------------------------------
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PromptShield Server] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
