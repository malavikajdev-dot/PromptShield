/**
 * PromptShield standalone MCP server (stateless Streamable HTTP).
 * Deploy as its own Render service, then register its public URL
 * (https://<service>.onrender.com/mcp) under Inventory -> MCP Servers on ArmorIQ.
 * All data is synthetic. Enforcement happens in ArmorIQ, not here.
 */
import express, { Request, Response, NextFunction } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { SYNTHETIC_CRM_RECORDS, SYNTHETIC_DOCUMENTS } from './syntheticData.ts';

const PORT = Number(process.env.PORT || 8080);
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || '';
const SERVER_NAME = 'promptshield-secure-mcp-server';

const text = (obj: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(obj) }],
});

function buildServer(): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: '1.0.0' });

  server.tool(
    'read_public_document',
    'Read a synthetic public demo document.',
    { path: z.string().optional() },
    async ({ path }) => {
      const key = path || 'doc:public/demo.txt';
      const doc = SYNTHETIC_DOCUMENTS[key];
      if (!doc || doc.scope !== 'public') return text({ success: false, error: `No public document at ${key}` });
      return text({ success: true, path: doc.path, title: doc.title, content: doc.content });
    }
  );

  server.tool(
    'summarize_customer_records',
    'Aggregated synthetic customer statistics (no raw PII).',
    { planFilter: z.string().optional() },
    async ({ planFilter }) => {
      let rows = SYNTHETIC_CRM_RECORDS;
      if (planFilter && planFilter !== 'ALL') rows = rows.filter((r) => r.plan.toLowerCase() === planFilter.toLowerCase());
      return text({
        success: true,
        totalCount: rows.length,
        aggregatedSpendUsd: rows.reduce((a, r) => a + r.syntheticSpendUsd, 0),
      });
    }
  );

  server.tool('list_permitted_resources', 'List public synthetic resources.', {}, async () =>
    text({
      success: true,
      publicResources: Object.values(SYNTHETIC_DOCUMENTS)
        .filter((d) => d.scope === 'public')
        .map((d) => ({ path: d.path, title: d.title })),
    })
  );

  // Sensitive tools: registered so ArmorIQ policies can deny them. Synthetic data only.
  server.tool(
    'read_restricted_file',
    'Read a restricted synthetic file (should be denied by policy).',
    { path: z.string().optional() },
    async ({ path }) => {
      const doc = SYNTHETIC_DOCUMENTS[path || 'doc:restricted/financials_q3.csv'];
      return text(doc ? { success: true, path: doc.path, content: doc.content } : { success: false, error: 'Not found' });
    }
  );

  server.tool('export_crm_records', 'Export raw synthetic CRM records (should be denied by policy).', {}, async () =>
    text({ success: true, records: SYNTHETIC_CRM_RECORDS })
  );

  server.tool(
    'draft_email',
    'Draft an email (never sent; sensitive egress).',
    { to: z.string().optional(), subject: z.string().optional(), body: z.string().optional() },
    async ({ to, subject, body }) => text({ success: true, status: 'DRAFT_ONLY_NOT_SENT', to, subject, body })
  );

  return server;
}

const app = express();
app.use(express.json());

function auth(req: Request, res: Response, next: NextFunction) {
  if (!AUTH_TOKEN) return next(); // open only if no token configured
  if (req.headers.authorization === `Bearer ${AUTH_TOKEN}`) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.get('/health', (_req, res) => res.json({ ok: true, server: SERVER_NAME }));

app.post('/mcp', auth, async (req: Request, res: Response) => {
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('MCP error:', err);
    if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
  }
});

app.get('/mcp', (_req, res) => res.status(405).json({ error: 'Method not allowed' }));

app.listen(PORT, () => console.log(`${SERVER_NAME} listening on ${PORT}`));
