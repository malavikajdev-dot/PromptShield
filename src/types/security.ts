/**
 * PromptShield Security & Trust Platform Type Definitions
 */

export type AuthorizationDecision = 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';

export type ToolExecutionStatus =
  | 'EXECUTED'
  | 'BLOCKED'
  | 'PENDING_APPROVAL'
  | 'APPROVED_AND_EXECUTED'
  | 'REJECTED';

export interface ToolActionProposal {
  tool_name: string;
  operation: string;
  parameters: Record<string, any>;
  reasoning: string;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  version: string;
  updatedAt: string;
  defaultDeny: boolean;
  permittedTools: string[];
  restrictedTools: string[];
  publicResourceScopes: string[];
  restrictedResourceScopes: string[];
  approvalRequiredOperations: string[];
  allowedExportDestinations: string[];
  enforcePathSanitization: boolean;
  maxExportRecordLimit: number;
}

export interface GatewayEvaluationResult {
  decision: AuthorizationDecision;
  reason: string;
  policyId: string;
  matchedRule: string;
  riskScore: number; // 0 (benign) to 100 (critical threat)
  timestamp: string;
  parametersValidated: boolean;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  testId: string;
  scenarioTitle: string;
  inputPrompt: string;
  proposedAction: ToolActionProposal;
  gatewayDecision: AuthorizationDecision;
  decisionReason: string;
  toolExecutionStatus: ToolExecutionStatus;
  toolResult: any;
  aiMode: 'gemini-3.8-flash' | 'deterministic-security-fallback-v1';
  policyId: string;
  prevHash: string;
  hash: string;
  isSimulatedTampered?: boolean;
}

export interface AuditIntegrityReport {
  isValid: boolean;
  totalRecords: number;
  verifiedAt: string;
  brokenRecordIndex: number | null;
  brokenRecordId: string | null;
  details: string;
  algorithm: string;
}

export interface AutomatedTestCase {
  id: string;
  category:
    | 'Benign Requests'
    | 'Prompt Injection'
    | 'Indirect Injection'
    | 'Privilege Escalation'
    | 'Data Exfiltration'
    | 'Parameter Tampering'
    | 'Audit Integrity';
  name: string;
  description: string;
  inputPrompt: string;
  scenarioKey: string;
  expectedDecision: AuthorizationDecision;
  expectedExecutionStatus: ToolExecutionStatus;
  status: 'IDLE' | 'PASS' | 'FAIL';
  actualDecision?: AuthorizationDecision;
  actualExecutionStatus?: ToolExecutionStatus;
  actualReason?: string;
  latencyMs?: number;
  timestamp?: string;
}

export interface PlaygroundTestResult {
  testId: string;
  timestamp: string;
  scenarioTitle: string;
  inputPrompt: string;
  aiAnalysis: {
    analysis: string;
    injection_detected: boolean;
    injection_confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    model: string;
    isFallback: boolean;
    latencyMs: number;
  };
  proposedAction: ToolActionProposal;
  gatewayEvaluation: GatewayEvaluationResult;
  toolExecution: {
    status: ToolExecutionStatus;
    result: any;
    executedAt: string;
    isRealMcpServer?: boolean;
    mcpServerInfo?: {
      name: string;
      version: string;
    };
  };
  armorIqAttestation?: {
    isConfigured: boolean;
    clientAuthenticated: boolean;
    intentToken?: {
      tokenId: string;
      planHash: string;
      planId?: string;
      signaturePreview: string;
      issuedAt: number;
      expiresAt: number;
      stepProofsCount: number;
      policyValidation?: any;
      compositeIdentity?: string;
    };
    planCaptureSummary?: {
      llm: string;
      goal: string;
      stepsCount: number;
      stepActions: string[];
    };
    bootstrapInfo?: {
      orgName: string;
      mcpCount: number;
      proxyEndpoint: string;
    };
    error?: string;
  };
  auditRecord: {
    id: string;
    hash: string;
  };
}

export interface ComparisonResult {
  inputPrompt: string;
  scenarioTitle: string;
  unprotectedBaseline: {
    proposedAction: ToolActionProposal;
    authorizationDecision: 'NONE (UNPROTECTED)';
    simulationWarning: string;
    simulatedExecutionResult: string;
    potentialImpact: string;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  };
  protectedAgent: {
    aiModel: string;
    isFallback: boolean;
    proposedAction: ToolActionProposal;
    gatewayDecision: AuthorizationDecision;
    decisionReason: string;
    toolExecutionStatus: ToolExecutionStatus;
    realExecutionResult: any;
    verifiableAuditHash: string;
    armorIqAttestation?: {
      isConfigured: boolean;
      tokenId?: string;
      planHash?: string;
    };
  };
}

export interface SystemHealthStatus {
  timestamp: string;
  frontend: {
    status: 'OPERATIONAL';
    details: string;
  };
  backendApi: {
    status: 'OPERATIONAL' | 'UNAVAILABLE';
    uptimeSeconds: number;
    details: string;
  };
  geminiApi: {
    status: 'CONFIGURED' | 'NOT_CONFIGURED' | 'FALLBACK_MODE';
    model: string;
    details: string;
  };
  securityPolicyEngine: {
    status: 'OPERATIONAL';
    activePolicyId: string;
    rulesEnforced: number;
    details: string;
  };
  auditStorage: {
    status: 'OPERATIONAL';
    storageType: 'DEVELOPMENT_LOCAL_PERSISTENT' | 'FIRESTORE';
    totalEvents: number;
    chainIntegrity: 'VALID' | 'TAMPER_DETECTED';
  };
  armorIq: {
    status: 'OPERATIONAL' | 'NOT_CONFIGURED';
    details: string;
    requirementsToEnable: string[];
  };
}
