/**
 * PromptShield Real MCP (Model Context Protocol) Server
 *
 * Implements an authentic Model Context Protocol Server using the official
 * @modelcontextprotocol/sdk with safe, read-only demo tools and synthetic data.
 *
 * Tools are registered strictly as read-only operations on synthetic data.
 * Tool execution is NEVER invoked directly by the AI agent; it requires upstream
 * cryptographic authorization from the ArmorIQ / PromptShield gateway.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { SYNTHETIC_CRM_RECORDS, SYNTHETIC_DOCUMENTS } from './syntheticData.ts';

export interface McpExecutionResult {
  toolName: string;
  success: boolean;
  content: Array<{ type: string; text?: string; data?: any }>;
  executedAt: string;
  isRealMcpServer: boolean;
  serverInfo: {
    name: string;
    version: string;
  };
}

let mcpServerInstance: McpServer | null = null;
let mcpClientInstance: Client | null = null;
let isInitialized = false;

/**
 * Initializes and connects the in-memory MCP Server and Client pair.
 */
export async function initializeMcpServer(): Promise<{
  server: McpServer;
  client: Client;
}> {
  if (isInitialized && mcpServerInstance && mcpClientInstance) {
    return { server: mcpServerInstance, client: mcpClientInstance };
  }

  const server = new McpServer({
    name: 'promptshield-secure-mcp-server',
    version: '1.0.0',
  });

  // Tool 1: read_public_document (Safe, Read-Only Demo Tool)
  server.tool(
    'read_public_document',
    'Read safe synthetic public demo documents from the sandboxed document registry.',
    async (args: any) => {
      const docPath = args?.path || 'doc:public/demo.txt';
      const doc = SYNTHETIC_DOCUMENTS[docPath];

      if (!doc) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: `Document not found at path: ${docPath}`,
                availablePublicDocs: Object.keys(SYNTHETIC_DOCUMENTS).filter((k) =>
                  k.startsWith('doc:public')
                ),
              }),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              path: doc.path,
              title: doc.title,
              scope: doc.scope,
              content: doc.content,
              byteLength: doc.content.length,
            }),
          },
        ],
      };
    }
  );

  // Tool 2: summarize_customer_records (Safe, Aggregated Read-Only Tool)
  server.tool(
    'summarize_customer_records',
    'Generate aggregated synthetic statistics for customer records without dumping raw PII.',
    async (args: any) => {
      const planFilter = args?.planFilter;
      let records = SYNTHETIC_CRM_RECORDS;

      if (planFilter && planFilter !== 'ALL') {
        records = records.filter(
          (r) => r.plan.toLowerCase() === String(planFilter).toLowerCase()
        );
      }

      const totalSyntheticSpend = records.reduce(
        (acc, curr) => acc + curr.syntheticSpendUsd,
        0
      );

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              totalCount: records.length,
              aggregatedSpendUsd: totalSyntheticSpend,
              summary: `Aggregated analysis for ${records.length} synthetic customer accounts across ${records.map((r) => r.region).join(', ')}.`,
              sampleRedactedRecords: records.map((r) => ({
                id: r.id,
                company: r.company,
                plan: r.plan,
                region: r.region,
              })),
            }),
          },
        ],
      };
    }
  );

  // Tool 3: list_permitted_resources (Safe Read-Only Catalog Tool)
  server.tool(
    'list_permitted_resources',
    'List all permitted demo resources available in the synthetic security testing sandbox.',
    async () => {
      const publicDocs = Object.values(SYNTHETIC_DOCUMENTS)
        .filter((d) => d.scope === 'public')
        .map((d) => ({ path: d.path, title: d.title, scope: d.scope }));

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              permittedTools: [
                'read_public_document',
                'summarize_customer_records',
                'list_permitted_resources',
              ],
              publicResources: publicDocs,
              message: 'Safe demo sandbox active with strictly read-only synthetic records.',
            }),
          },
        ],
      };
    }
  );

  // Connect via MCP In-Memory Transport Pair
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  const client = new Client(
    { name: 'promptshield-gateway-client', version: '1.0.0' },
    { capabilities: {} }
  );
  await client.connect(clientTransport);

  mcpServerInstance = server;
  mcpClientInstance = client;
  isInitialized = true;

  return { server, client };
}

/**
 * Execute a tool on the real MCP Server.
 * CRITICAL RULE: This function MUST ONLY be called if the Authorization Gateway
 * issued an explicit ALLOW. If authorization was blocked, this function is NOT invoked.
 */
export async function executeMcpToolCall(
  toolName: string,
  params: Record<string, any> = {}
): Promise<McpExecutionResult> {
  const { client } = await initializeMcpServer();
  const executedAt = new Date().toISOString();

  try {
    const response = await client.callTool({
      name: toolName,
      arguments: params,
    });

    return {
      toolName,
      success: true,
      content: (response.content as any[]) || [],
      executedAt,
      isRealMcpServer: true,
      serverInfo: {
        name: 'promptshield-secure-mcp-server',
        version: '1.0.0',
      },
    };
  } catch (err: any) {
    return {
      toolName,
      success: false,
      content: [{ type: 'text', text: `MCP Execution Error: ${err?.message || 'Tool failed'}` }],
      executedAt,
      isRealMcpServer: true,
      serverInfo: {
        name: 'promptshield-secure-mcp-server',
        version: '1.0.0',
      },
    };
  }
}

/**
 * Returns the list of registered tools from the MCP server.
 */
export async function getMcpRegisteredTools(): Promise<string[]> {
  const { client } = await initializeMcpServer();
  const list = await client.listTools();
  return list.tools.map((t) => t.name);
}
