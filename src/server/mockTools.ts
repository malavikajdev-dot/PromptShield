/**
 * PromptShield Sandboxed Synthetic Tools Implementation
 *
 * All operations run strictly on synthetic data in an isolated sandbox.
 * Tools are NEVER called if the Authorization Gateway issued a BLOCK.
 */

import {
  SYNTHETIC_CRM_RECORDS,
  SYNTHETIC_DOCUMENTS,
} from './syntheticData.ts';
import { ToolActionProposal, ToolExecutionStatus } from '../types/security.ts';
import { executeMcpToolCall } from './mcpServer.ts';

export interface ToolExecutionResponse {
  status: ToolExecutionStatus;
  result: any;
  error?: string;
  executionTimestamp: string;
  isRealMcpServer?: boolean;
  mcpServerInfo?: {
    name: string;
    version: string;
  };
}

/**
 * Execute tool action through the controlled sandbox.
 * Precondition: The Gateway MUST have evaluated the proposal.
 */
export async function executeSandboxedTool(
  proposal: ToolActionProposal,
  gatewayDecision: 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED'
): Promise<ToolExecutionResponse> {
  const executionTimestamp = new Date().toISOString();

  // Rule: If Gateway BLOCKED the action, the tool code MUST NOT run.
  if (gatewayDecision === 'BLOCK') {
    return {
      status: 'BLOCKED',
      result: {
        error: 'Execution Intercepted: Server authorization gateway denied this action.',
        tool: proposal.tool_name,
        operation: proposal.operation,
        mcpGating: 'Real MCP tool execution PREVENTED. Zero calls reached the MCP server.',
      },
      executionTimestamp,
    };
  }

  // Rule: If Gateway flagged APPROVAL_REQUIRED, the tool enters PENDING state.
  if (gatewayDecision === 'APPROVAL_REQUIRED') {
    return {
      status: 'PENDING_APPROVAL',
      result: {
        message: 'Action suspended in Gateway Hold. Awaiting administrative human approval.',
        tool: proposal.tool_name,
        operation: proposal.operation,
        parameters: proposal.parameters,
      },
      executionTimestamp,
    };
  }

  // Gateway issued ALLOW: execute via the real MCP Server when applicable
  try {
    if (
      proposal.tool_name === 'read_public_document' ||
      proposal.tool_name === 'summarize_customer_records' ||
      proposal.tool_name === 'list_permitted_resources'
    ) {
      const mcpResponse = await executeMcpToolCall(
        proposal.tool_name,
        proposal.parameters || {}
      );

      let parsedResult: any = mcpResponse.content;
      if (mcpResponse.content?.[0]?.text) {
        try {
          parsedResult = JSON.parse(mcpResponse.content[0].text);
        } catch {
          parsedResult = mcpResponse.content[0].text;
        }
      }

      return {
        status: 'EXECUTED',
        result: parsedResult,
        executionTimestamp,
        isRealMcpServer: true,
        mcpServerInfo: mcpResponse.serverInfo,
      };
    }

    switch (proposal.tool_name) {
      case 'draft_email': {
        const to = proposal.parameters?.to || 'internal-team@promptshield.local';
        const subject = proposal.parameters?.subject || 'Security Verification Notification';
        const body = proposal.parameters?.body || 'This is a synthetic draft email notification.';

        return {
          status: 'EXECUTED',
          result: {
            success: true,
            draftId: `draft-syn-${Date.now().toString().slice(-6)}`,
            status: 'DRAFT_SAVED_LOCAL_ONLY',
            to,
            subject,
            bodyPreview: body.length > 80 ? body.substring(0, 80) + '...' : body,
            safetyNotice: 'Synthetic draft created locally in demo sandbox. No external network request was emitted.',
          },
          executionTimestamp,
        };
      }

      case 'list_permitted_resources': {
        const publicDocs = Object.values(SYNTHETIC_DOCUMENTS)
          .filter((d) => d.scope === 'public')
          .map((d) => ({ path: d.path, title: d.title, scope: d.scope }));

        return {
          status: 'EXECUTED',
          result: {
            success: true,
            availableTools: [
              'read_public_document',
              'summarize_customer_records',
              'draft_email',
              'list_permitted_resources',
            ],
            publicResources: publicDocs,
            message: 'All returned resources operate under active least-privilege sandbox scope.',
          },
          executionTimestamp,
        };
      }

      // If an ALLOW was somehow triggered for a dangerous tool in relaxed policy testing:
      case 'read_restricted_file': {
        const path = proposal.parameters?.path || 'doc:restricted/financials_q3.csv';
        const doc = SYNTHETIC_DOCUMENTS[path];
        return {
          status: 'EXECUTED',
          result: {
            success: true,
            warning: 'TEST MODE: Restricted document read executed in permissive testing policy.',
            path,
            content: doc?.content || 'SYNTHETIC_RESTRICTED_DATA_REDACTED',
          },
          executionTimestamp,
        };
      }

      case 'export_crm_records': {
        return {
          status: 'EXECUTED',
          result: {
            success: true,
            exportedCount: SYNTHETIC_CRM_RECORDS.length,
            destination: proposal.parameters?.destination,
            format: proposal.parameters?.format || 'JSON',
            safetyNotice: 'Synthetic export completed to authorized internal destination.',
          },
          executionTimestamp,
        };
      }

      default:
        return {
          status: 'BLOCKED',
          result: {
            error: `Unknown tool '${proposal.tool_name}'. Blocked by sandboxed runner.`,
          },
          executionTimestamp,
        };
    }
  } catch (err: any) {
    return {
      status: 'BLOCKED',
      result: {
        error: `Tool execution runtime error: ${err?.message || 'Unknown error'}`,
      },
      executionTimestamp,
    };
  }
}
