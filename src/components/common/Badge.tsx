import React from 'react';
import { AuthorizationDecision, ToolExecutionStatus } from '../../types/security.ts';
import { CheckCircle2, ShieldAlert, AlertTriangle, Clock, Ban } from 'lucide-react';

interface DecisionBadgeProps {
  decision: AuthorizationDecision | 'NONE (UNPROTECTED)';
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export function DecisionBadge({ decision, size = 'md', showIcon = true }: DecisionBadgeProps) {
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs sm:text-sm px-2.5 py-1',
    lg: 'text-sm sm:text-base px-3.5 py-1.5 font-semibold',
  };

  switch (decision) {
    case 'ALLOW':
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-medium ${sizeClasses[size]}`}
        >
          {showIcon && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
          <span>ALLOW</span>
        </span>
      );

    case 'BLOCK':
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/15 text-rose-400 font-medium ${sizeClasses[size]}`}
        >
          {showIcon && <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />}
          <span>BLOCK</span>
        </span>
      );

    case 'APPROVAL_REQUIRED':
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/15 text-amber-400 font-medium ${sizeClasses[size]}`}
        >
          {showIcon && <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />}
          <span>APPROVAL REQUIRED</span>
        </span>
      );

    case 'NONE (UNPROTECTED)':
    default:
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-red-600/50 bg-red-950/60 text-red-300 font-bold tracking-wide ${sizeClasses[size]}`}
        >
          {showIcon && <Ban className="w-4 h-4 text-red-400 shrink-0" />}
          <span>UNPROTECTED</span>
        </span>
      );
  }
}

export function StatusBadge({ status }: { status: ToolExecutionStatus }) {
  switch (status) {
    case 'EXECUTED':
    case 'APPROVED_AND_EXECUTED':
      return (
        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          {status === 'APPROVED_AND_EXECUTED' ? 'Approved & Executed' : 'Executed in Sandbox'}
        </span>
      );
    case 'BLOCKED':
      return (
        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-300">
          <ShieldAlert className="w-3 h-3 text-rose-400" />
          Blocked by Gateway
        </span>
      );
    case 'PENDING_APPROVAL':
      return (
        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-300">
          <Clock className="w-3 h-3 text-amber-400" />
          Pending Human Approval
        </span>
      );
    case 'REJECTED':
      return (
        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-slate-600 bg-slate-800 text-slate-300">
          Rejected
        </span>
      );
    default:
      return <span className="text-xs text-slate-400">{status}</span>;
  }
}
