/**
 * PromptShield Server-Side Security Policy Engine & Authorization Gateway
 *
 * Implements strict zero-trust server-side validation.
 * Crucial Rule: The gateway operates completely independently of the AI model's
 * self-assessment. Prompts cannot grant permissions, escalate roles, or alter policies.
 */

import {
  AuthorizationDecision,
  GatewayEvaluationResult,
  SecurityPolicy,
  ToolActionProposal,
} from '../types/security.ts';

export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
  id: 'policy-prod-standard-v1',
  name: 'Standard Zero-Trust AI Agent Policy',
  version: '1.4.0',
  updatedAt: new Date().toISOString(),
  defaultDeny: true,
  permittedTools: [
    'read_public_document',
    'summarize_customer_records',
    'draft_email',
    'list_permitted_resources',
  ],
  restrictedTools: [
    'read_restricted_file',
    'export_crm_records',
    'execute_shell_command',
    'modify_security_policy',
  ],
  publicResourceScopes: [
    'doc:public/demo.txt',
    'doc:public/system_guidelines.md',
    'doc:public/faq.txt',
  ],
  restrictedResourceScopes: [
    'doc:restricted/financials_q3.csv',
    'doc:restricted/api_keys.vault',
    'doc:restricted/confidential_client_list.pdf',
    'crm:all_customers_export',
    'auth:admin_tokens',
  ],
  approvalRequiredOperations: [
    'draft_email.send_external',
    'export_crm_records.synthetic_export',
    'summarize_customer_records.raw_data_dump',
  ],
  allowedExportDestinations: [
    'internal-crm.enterprise.local',
    'sec-audit@promptshield.io',
    'safe-sandbox@internal.test',
  ],
  enforcePathSanitization: true,
  maxExportRecordLimit: 10,
};

// In-memory active policy (with reset and update capabilities)
let activePolicy: SecurityPolicy = { ...DEFAULT_SECURITY_POLICY };

export function getActivePolicy(): SecurityPolicy {
  return { ...activePolicy };
}

export function resetPolicyToDefault(): SecurityPolicy {
  activePolicy = {
    ...DEFAULT_SECURITY_POLICY,
    updatedAt: new Date().toISOString(),
  };
  return { ...activePolicy };
}

export function updateSecurityPolicy(
  incomingPolicy: Partial<SecurityPolicy>
): { success: boolean; policy?: SecurityPolicy; error?: string } {
  try {
    if (!incomingPolicy) {
      return { success: false, error: 'Policy payload cannot be empty.' };
    }

    // Validate permitted tools is an array of strings
    if (incomingPolicy.permittedTools && !Array.isArray(incomingPolicy.permittedTools)) {
      return { success: false, error: 'permittedTools must be an array of strings.' };
    }

    // Validate restricted tools is an array of strings
    if (incomingPolicy.restrictedTools && !Array.isArray(incomingPolicy.restrictedTools)) {
      return { success: false, error: 'restrictedTools must be an array of strings.' };
    }

    // Validate destinations
    if (incomingPolicy.allowedExportDestinations && !Array.isArray(incomingPolicy.allowedExportDestinations)) {
      return { success: false, error: 'allowedExportDestinations must be an array of strings.' };
    }

    activePolicy = {
      ...activePolicy,
      ...incomingPolicy,
      id: incomingPolicy.id || activePolicy.id,
      version: incomingPolicy.version || `1.4.${Date.now().toString().slice(-4)}`,
      updatedAt: new Date().toISOString(),
    };

    return { success: true, policy: { ...activePolicy } };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Failed to update policy' };
  }
}

/**
 * Real Backend Authorization Gateway
 * Evaluates the proposed tool action against the active policy.
 * NEVER trusts the prompt's claims. Fails closed (BLOCK) on any anomaly.
 */
export function evaluateAuthorizationGateway(
  proposal: ToolActionProposal,
  userContext: { role: string; origin: string } = { role: 'tester', origin: 'web_playground' }
): GatewayEvaluationResult {
  const timestamp = new Date().toISOString();
  const policy = activePolicy;

  // Fail-safe: if proposal is malformed, block immediately
  if (!proposal || !proposal.tool_name) {
    return {
      decision: 'BLOCK',
      reason: 'Gateway Intercept: Malformed or missing tool action proposal.',
      policyId: policy.id,
      matchedRule: 'MALFORMED_PROPOSAL',
      riskScore: 90,
      timestamp,
      parametersValidated: false,
    };
  }

  const toolName = proposal.tool_name.trim();
  const operation = proposal.operation ? proposal.operation.trim() : 'default';
  const params = proposal.parameters || {};

  // 1. Strict Path Traversal and Command Injection Inspection
  if (policy.enforcePathSanitization) {
    const stringifiedParams = JSON.stringify(params);
    const traversalPatterns = [
      /\.\.\//, // ../
      /\.\.\\/, // ..\
      /\/etc\//i,
      /\/proc\//i,
      /C:\\Windows/i,
      /;\s*(rm|del|cat|curl|wget|sh|bash)/i,
    ];

    for (const pattern of traversalPatterns) {
      if (pattern.test(stringifiedParams)) {
        return {
          decision: 'BLOCK',
          reason: 'Gateway Intercept: Path traversal or malicious command characters detected in tool parameters.',
          policyId: policy.id,
          matchedRule: 'ENFORCE_PATH_SANITIZATION',
          riskScore: 95,
          timestamp,
          parametersValidated: false,
        };
      }
    }
  }

  // 2. Explicit Restricted Tools Check
  if (policy.restrictedTools.includes(toolName)) {
    return {
      decision: 'BLOCK',
      reason: `Gateway Deny: Tool '${toolName}' is classified as a Restricted High-Risk Tool under active policy '${policy.id}'.`,
      policyId: policy.id,
      matchedRule: 'EXPLICIT_RESTRICTED_TOOL',
      riskScore: 85,
      timestamp,
      parametersValidated: true,
    };
  }

  // 3. Default Deny Check
  if (policy.defaultDeny && !policy.permittedTools.includes(toolName)) {
    return {
      decision: 'BLOCK',
      reason: `Gateway Deny (Default-Deny): Tool '${toolName}' is not registered in the Permitted Tools whitelist.`,
      policyId: policy.id,
      matchedRule: 'DEFAULT_DENY_ENFORCEMENT',
      riskScore: 80,
      timestamp,
      parametersValidated: true,
    };
  }

  // 4. Resource Scope Authorization Checks
  const targetResource = params.path || params.resource || params.target;
  if (targetResource && typeof targetResource === 'string') {
    // Check if target matches any restricted resource scopes
    const isRestrictedResource = policy.restrictedResourceScopes.some((restrictedScope) =>
      targetResource.toLowerCase().includes(restrictedScope.toLowerCase()) ||
      targetResource.toLowerCase().includes('restricted') ||
      targetResource.toLowerCase().includes('api_keys') ||
      targetResource.toLowerCase().includes('financials')
    );

    if (isRestrictedResource) {
      return {
        decision: 'BLOCK',
        reason: `Gateway Intercept: Resource '${targetResource}' resides in restricted scope. User role '${userContext.role}' lacks elevation clearance.`,
        policyId: policy.id,
        matchedRule: 'RESTRICTED_RESOURCE_SCOPE',
        riskScore: 90,
        timestamp,
        parametersValidated: true,
      };
    }
  }

  // 5. Approval-Required Operations Check (Human-in-the-loop Gate)
  const opKey = `${toolName}.${operation}`;
  const requiresApproval =
    policy.approvalRequiredOperations.includes(opKey) ||
    policy.approvalRequiredOperations.includes(toolName) ||
    (toolName === 'draft_email' && (params.sendImmediately === true || operation === 'send_external')) ||
    (toolName === 'export_crm_records' && (params.recordCount || 0) > policy.maxExportRecordLimit);

  if (requiresApproval) {
    return {
      decision: 'APPROVAL_REQUIRED',
      reason: `Gateway Hold: Operation '${opKey}' is tagged as Sensitive. Requires authorized human administrator approval prior to execution.`,
      policyId: policy.id,
      matchedRule: 'APPROVAL_REQUIRED_POLICY',
      riskScore: 50,
      timestamp,
      parametersValidated: true,
    };
  }

  // 6. Destination Verification (for emails or data exports)
  const destination = params.destination || params.to || params.recipient;
  if (destination && typeof destination === 'string') {
    const isAllowedDestination = policy.allowedExportDestinations.some((allowed) =>
      destination.toLowerCase().includes(allowed.toLowerCase())
    );

    if (!isAllowedDestination) {
      // If tool is export or email sending to external unknown host
      return {
        decision: 'BLOCK',
        reason: `Gateway Intercept: Recipient destination '${destination}' is not in the authorized egress whitelist. Exfiltration blocked.`,
        policyId: policy.id,
        matchedRule: 'EGRESS_DESTINATION_MISMATCH',
        riskScore: 90,
        timestamp,
        parametersValidated: true,
      };
    }
  }

  // 7. Legitimate Permitted Action
  return {
    decision: 'ALLOW',
    reason: `Gateway Verified: Tool '${toolName}' and operation '${operation}' satisfy all whitelist policies. Action authorized for sandbox execution.`,
    policyId: policy.id,
    matchedRule: 'PERMITTED_LEAST_PRIVILEGE',
    riskScore: 5,
    timestamp,
    parametersValidated: true,
  };
}
