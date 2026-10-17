import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  RotateCcw,
  Save,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Plus,
  Trash2,
  Info,
} from 'lucide-react';
import { SecurityPolicy } from '../../types/security.ts';
import { fetchPolicy, resetPolicy, savePolicy } from '../../services/api.ts';

export function PoliciesView() {
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Temporary inputs for adding list items
  const [newPermittedTool, setNewPermittedTool] = useState('');
  const [newRestrictedScope, setNewRestrictedScope] = useState('');
  const [newAllowedDestination, setNewAllowedDestination] = useState('');
  const [newApprovalOp, setNewApprovalOp] = useState('');

  const loadPolicy = async () => {
    try {
      setLoading(true);
      const data = await fetchPolicy();
      setPolicy(data);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err.message || 'Failed to load policy' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicy();
  }, []);

  const handleSavePolicy = async () => {
    if (!policy) return;
    try {
      setSaving(true);
      setStatusMsg(null);
      const updated = await savePolicy(policy);
      setPolicy(updated);
      setStatusMsg({ type: 'success', text: 'Security policy successfully saved and active in the gateway!' });
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err.message || 'Failed to save policy' });
    } finally {
      setSaving(false);
    }
  };

  const handleResetDefaults = async () => {
    if (!confirm('Reset security policy to default zero-trust posture?')) return;
    try {
      setSaving(true);
      setStatusMsg(null);
      const res = await resetPolicy();
      setPolicy(res.policy);
      setStatusMsg({ type: 'success', text: 'Policy restored to factory zero-trust configuration.' });
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err.message || 'Reset failed' });
    } finally {
      setSaving(false);
    }
  };

  const removeArrayItem = (key: keyof SecurityPolicy, index: number) => {
    if (!policy) return;
    const arr = [...(policy[key] as string[])];
    arr.splice(index, 1);
    setPolicy({ ...policy, [key]: arr });
  };

  const addArrayItem = (key: keyof SecurityPolicy, value: string, clearFn: () => void) => {
    if (!policy || !value.trim()) return;
    const arr = [...(policy[key] as string[])];
    if (!arr.includes(value.trim())) {
      arr.push(value.trim());
      setPolicy({ ...policy, [key]: arr });
    }
    clearFn();
  };

  if (loading || !policy) {
    return (
      <div className="p-12 text-center text-slate-400 text-sm">
        <div className="w-6 h-6 border-2 border-sky-400 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
        Loading security policies...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-400/30">
                Server-Side Enforcement
              </span>
              <span className="text-xs text-slate-400 font-mono">ID: {policy.id}</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">Zero-Trust Security Policies</h2>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              Rules defined here are evaluated independently of AI prompts. 
              Changes are validated on the backend before being applied to the live gateway.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleResetDefaults}
              disabled={saving}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-medium cursor-pointer transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset to Defaults</span>
            </button>
            <button
              onClick={handleSavePolicy}
              disabled={saving}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:bg-slate-800 text-slate-950 font-bold text-xs cursor-pointer shadow-[0_0_12px_rgba(56,189,248,0.3)] transition-colors"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? 'Saving...' : 'Apply Policy Changes'}</span>
            </button>
          </div>
        </div>

        {statusMsg && (
          <div
            className={`mt-4 p-3 rounded-lg text-xs flex items-center gap-2 border ${
              statusMsg.type === 'success'
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
            }`}
          >
            {statusMsg.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span>{statusMsg.text}</span>
          </div>
        )}
      </div>

      {/* Global Flags */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Default-Deny Card */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-bold text-white">Default-Deny Enforcement</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              When enabled, any tool or action not explicitly listed in the whitelist is blocked by default.
            </p>
          </div>
          <button
            onClick={() => setPolicy({ ...policy, defaultDeny: !policy.defaultDeny })}
            className={`w-12 h-6 rounded-full p-1 transition-colors relative cursor-pointer shrink-0 ${
              policy.defaultDeny ? 'bg-sky-500' : 'bg-slate-800'
            }`}
          >
            <div
              className={`w-4 h-4 rounded-full bg-white transition-transform ${
                policy.defaultDeny ? 'translate-x-6' : 'translate-x-0'
              }`}
            />
          </button>
        </div>

        {/* Path Sanitization Card */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Path Traversal Sanitization</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Scans all incoming parameters for relative path traversal patterns (e.g., ../ or /etc/passwd).
            </p>
          </div>
          <button
            onClick={() =>
              setPolicy({ ...policy, enforcePathSanitization: !policy.enforcePathSanitization })
            }
            className={`w-12 h-6 rounded-full p-1 transition-colors relative cursor-pointer shrink-0 ${
              policy.enforcePathSanitization ? 'bg-sky-500' : 'bg-slate-800'
            }`}
          >
            <div
              className={`w-4 h-4 rounded-full bg-white transition-transform ${
                policy.enforcePathSanitization ? 'translate-x-6' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>

      {/* Policy Lists Configuration Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 1. Permitted Tools Whitelist */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <h3 className="text-sm font-semibold text-white">Permitted Tools Whitelist</h3>
              <p className="text-[11px] text-slate-400">Tools authorized for sandboxed agent invocation</p>
            </div>
            <span className="text-xs font-mono text-emerald-400 font-semibold">
              {policy.permittedTools.length} tools
            </span>
          </div>

          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {policy.permittedTools.map((tool, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0a0f1d] border border-slate-800 text-xs font-mono text-slate-200"
              >
                <span>{tool}</span>
                <button
                  onClick={() => removeArrayItem('permittedTools', idx)}
                  className="text-slate-500 hover:text-rose-400 p-1 cursor-pointer"
                  title="Remove tool"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          <div className="flex gap-2 pt-2">
            <input
              type="text"
              value={newPermittedTool}
              onChange={(e) => setNewPermittedTool(e.target.value)}
              placeholder="e.g. read_public_document"
              className="flex-1 bg-[#0a0f1d] border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              onClick={() =>
                addArrayItem('permittedTools', newPermittedTool, () => setNewPermittedTool(''))
              }
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add</span>
            </button>
          </div>
        </div>

        {/* 2. Restricted Resource Scopes */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <h3 className="text-sm font-semibold text-white">Restricted Resource Scopes</h3>
              <p className="text-[11px] text-slate-400">Vaults and scopes inaccessible to testing agents</p>
            </div>
            <span className="text-xs font-mono text-rose-400 font-semibold">
              {policy.restrictedResourceScopes.length} scopes
            </span>
          </div>

          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {policy.restrictedResourceScopes.map((scope, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0a0f1d] border border-slate-800 text-xs font-mono text-rose-300"
              >
                <span>{scope}</span>
                <button
                  onClick={() => removeArrayItem('restrictedResourceScopes', idx)}
                  className="text-slate-500 hover:text-rose-400 p-1 cursor-pointer"
                  title="Remove scope"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          <div className="flex gap-2 pt-2">
            <input
              type="text"
              value={newRestrictedScope}
              onChange={(e) => setNewRestrictedScope(e.target.value)}
              placeholder="e.g. doc:restricted/vault_tokens.pem"
              className="flex-1 bg-[#0a0f1d] border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              onClick={() =>
                addArrayItem('restrictedResourceScopes', newRestrictedScope, () =>
                  setNewRestrictedScope('')
                )
              }
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add</span>
            </button>
          </div>
        </div>

        {/* 3. Human Approval Gates */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <h3 className="text-sm font-semibold text-white">Approval-Required Operations</h3>
              <p className="text-[11px] text-slate-400">Operations requiring administrative human approval</p>
            </div>
            <span className="text-xs font-mono text-amber-400 font-semibold">
              {policy.approvalRequiredOperations.length} operations
            </span>
          </div>

          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {policy.approvalRequiredOperations.map((op, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0a0f1d] border border-slate-800 text-xs font-mono text-amber-300"
              >
                <span>{op}</span>
                <button
                  onClick={() => removeArrayItem('approvalRequiredOperations', idx)}
                  className="text-slate-500 hover:text-rose-400 p-1 cursor-pointer"
                  title="Remove operation"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          <div className="flex gap-2 pt-2">
            <input
              type="text"
              value={newApprovalOp}
              onChange={(e) => setNewApprovalOp(e.target.value)}
              placeholder="e.g. draft_email.send_external"
              className="flex-1 bg-[#0a0f1d] border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              onClick={() =>
                addArrayItem('approvalRequiredOperations', newApprovalOp, () =>
                  setNewApprovalOp('')
                )
              }
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add</span>
            </button>
          </div>
        </div>

        {/* 4. Allowed Egress Destinations */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <h3 className="text-sm font-semibold text-white">Allowed Egress Destinations</h3>
              <p className="text-[11px] text-slate-400">Permitted external email & webhook domains</p>
            </div>
            <span className="text-xs font-mono text-sky-400 font-semibold">
              {policy.allowedExportDestinations.length} domains
            </span>
          </div>

          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {policy.allowedExportDestinations.map((dest, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0a0f1d] border border-slate-800 text-xs font-mono text-slate-300"
              >
                <span>{dest}</span>
                <button
                  onClick={() => removeArrayItem('allowedExportDestinations', idx)}
                  className="text-slate-500 hover:text-rose-400 p-1 cursor-pointer"
                  title="Remove destination"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          <div className="flex gap-2 pt-2">
            <input
              type="text"
              value={newAllowedDestination}
              onChange={(e) => setNewAllowedDestination(e.target.value)}
              placeholder="e.g. internal-crm.enterprise.local"
              className="flex-1 bg-[#0a0f1d] border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              onClick={() =>
                addArrayItem('allowedExportDestinations', newAllowedDestination, () =>
                  setNewAllowedDestination('')
                )
              }
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
