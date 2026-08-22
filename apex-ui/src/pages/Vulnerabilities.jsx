import React, { useState, useEffect, useCallback, useRef } from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  BUSINESS_OPTIONS,
  OWNER_OPTIONS,
  PRIORITY_RANK,
  SLA_DAYS,
  TICKET_STATES,
  WORKFLOW_STORAGE_KEY,
  addDays,
  applyRetestTruth,
  hydrateWorkflow,
  normalizeFindingTruth,
} from '../utils/vulnerabilityWorkflow';

import { apiFetch } from '../config/api';
import { applyActionConfirmations, dashboardErrorMessage, prepareActionConfirmations } from '../utils/actionConfirmation';

/* ── Populated by backend /api/v1/findings + WebSocket live updates ── */
const SEED_VULNS = [];

const STATUS_OPTIONS = ['Open', 'In Progress', 'Fixed', 'Accepted', 'False Positive'];

// Backend truth is lower-case and API-shaped; the workflow controls use the
// same title-cased labels as the existing operator UI.  This adapter keeps the
// normalized status visible rather than replacing live findings with a local
// optimistic "Open" default.
const displayStatus = (value) => {
  const normalized = String(value || 'open').trim().toLowerCase();
  const labels = {
    open: 'Open',
    in_progress: 'In Progress',
    'in progress': 'In Progress',
    fixed: 'Fixed',
    remediated: 'Fixed',
    accepted: 'Accepted',
    accepted_risk: 'Accepted',
    false_positive: 'False Positive',
  };
  return labels[normalized] || value || 'Open';
};

const statusBadge = (s) => {
  if (s === 'Open') return 'critical';
  if (s === 'In Progress') return 'medium';
  if (s === 'Fixed') return 'active';
  if (s === 'Accepted') return 'info';
  if (s === 'False Positive') return 'default';
  return 'default';
};

const severityColor = {
  critical: 'var(--color-critical)',
  high:     'var(--color-high)',
  medium:   'var(--color-medium)',
  low:      'var(--color-low)',
  info:     'var(--color-info)',
};

const confidenceColor = {
  HIGH:   'var(--color-success)',
  MEDIUM: 'var(--color-medium)',
  LOW:    'var(--color-high)',
};

const loadWorkflowMeta = () => {
  try {
    return JSON.parse(window.localStorage.getItem(WORKFLOW_STORAGE_KEY)) || {};
  } catch {
    return {};
  }
};

const saveWorkflowMeta = (meta) => {
  try {
    window.localStorage.setItem(WORKFLOW_STORAGE_KEY, JSON.stringify(meta));
  } catch {}
};

const Vulnerabilities = ({ authToken }) => {
  const { lastMessage } = useWebSocket(undefined, authToken);

  // Data
  const [vulns, setVulns]           = useState(SEED_VULNS);
  const [filterSev, setFilterSev]   = useState(new Set(['critical','high','medium','low','info']));
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterTarget, setFilterTarget] = useState('all');
  const [filterOwner, setFilterOwner] = useState('all');
  const [filterSla, setFilterSla] = useState('all');
  const [sortBy, setSortBy]         = useState('cvss');
  const [workflowMeta, setWorkflowMeta] = useState(loadWorkflowMeta);

  // Slide-out panel
  const [selectedId, setSelectedId] = useState(null);
  const panelRef = useRef(null);

  // Bulk selection
  const [checked, setChecked]     = useState(new Set());
  const [bulkAction, setBulkAction] = useState('');

  // Re-test state
  const [retesting, setRetesting] = useState(null);  // finding_id being retested
  const [retestError, setRetestError] = useState('');

  // Status update state
  const [statusUpdating, setStatusUpdating] = useState(null);

  useEffect(() => {
    saveWorkflowMeta(workflowMeta);
  }, [workflowMeta]);

  const hydratedVulns = React.useMemo(
    () => vulns.map(v => hydrateWorkflow(v, workflowMeta)),
    [vulns, workflowMeta]
  );

  const selected = hydratedVulns.find(v => v.id === selectedId) || null;

  // Fetch findings from backend on mount
  useEffect(() => {
    apiFetch('/api/v1/findings?limit=200')
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d?.findings?.length) {
          setVulns(d.findings.map((f, i) => ({
            ...normalizeFindingTruth(f),
            status: displayStatus(f.status),
            id: f.id || f.finding_id || `f-${i}`,
            cve: f.cve || '',
            finding: f.title || f.finding || '',
            target: f.target || '',
            cvss: f.cvss || 0,
            vpr: f.vpr_score || f.vpr || 0,
            severity: (f.severity || 'info').toLowerCase(),
            module: f.module || '',
            description: f.description || '',
            repro: f.reproduction_steps || f.repro || '',
            evidence: f.evidence || '',
            remediation: f.remediation || '',
            owner: f.owner || 'Unassigned',
            businessImpact: f.business_impact || f.businessImpact || (f.severity === 'critical' ? 'Critical Service' : 'Unknown'),
            dueDate: f.due_date || f.dueDate || addDays(SLA_DAYS[(f.severity || 'info').toLowerCase()] || 90),
            ticketState: f.ticket_state || f.ticketState || 'Not Filed',
            ticketId: f.ticket_id || f.ticketId || '',
            queueNote: f.queue_note || f.queueNote || '',
          })));
        }
      })
      .catch(() => {}); // backend offline — keep seed data
  }, []);

  // Live finding updates from WebSocket
  useEffect(() => {
    if (!lastMessage) return;
    const { type, event_type, data } = lastMessage;
    if (type !== 'event') return;
    if (event_type === 'finding_new') {
      const truth = normalizeFindingTruth(data);
      setVulns(prev => [{
        ...truth,
        status: displayStatus(truth.status),
        id: data.id || data.finding_id || `f-live-${Date.now()}`,
        cve: data.cve || '',
        finding: data.title || '',
        target: data.target || '',
        cvss: data.cvss || 0,
        vpr: data.vpr || 0,
        severity: (data.severity || 'info').toLowerCase(),
        module: data.module || '',
        description: data.description || '',
        repro: data.repro || '',
        evidence: data.evidence || '',
        remediation: data.remediation || '',
        owner: 'Unassigned',
        businessImpact: (data.severity || '').toLowerCase() === 'critical' ? 'Critical Service' : 'Unknown',
        dueDate: addDays(SLA_DAYS[(data.severity || 'info').toLowerCase()] || 90),
        ticketState: 'Not Filed',
        ticketId: '',
        queueNote: '',
      }, ...prev]);
    }
    if (event_type === 'finding_updated' && (data.finding_id || data.id)) {
      const truth = normalizeFindingTruth(data);
      const findingId = data.finding_id || data.id;
      const truthPatch = Object.fromEntries(
        ['confidence', 'verification_state', 'proof_type', 'maturity', 'retest_status']
          .filter(key => Object.prototype.hasOwnProperty.call(data, key))
          .map(key => [key, truth[key]])
      );
      setVulns(prev => prev.map(v =>
        (v.id === findingId) ? {
          ...v,
          ...truthPatch,
          status: data.status ? displayStatus(truth.status) : v.status,
        } : v
      ));
    }
  }, [lastMessage]);

  // Escape key closes panel
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') setSelectedId(null); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Outside click closes panel
  useEffect(() => {
    const handler = (e) => {
      if (selectedId && panelRef.current && !panelRef.current.contains(e.target)) {
        // Don't close if clicking a table row (that selects a new finding)
        if (e.target.closest('tr')) return;
        setSelectedId(null);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [selectedId]);

  // Filtered + sorted vulns
  const displayVulns = [...hydratedVulns]
    .filter(v => filterSev.has(v.severity))
    .filter(v => filterStatus === 'all' || v.status === filterStatus)
    .filter(v => filterTarget === 'all' || v.target === filterTarget)
    .filter(v => filterOwner === 'all' || v.owner === filterOwner)
    .filter(v => filterSla === 'all' || v.slaState === filterSla)
    .sort((a, b) => {
      if (sortBy === 'cvss') return b.cvss - a.cvss;
      if (sortBy === 'vpr') return (b.vpr || 0) - (a.vpr || 0);
      if (sortBy === 'priority') return PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority];
      if (sortBy === 'sla') return (a.slaDays ?? 9999) - (b.slaDays ?? 9999);
      if (sortBy === 'severity') {
        const ord = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (ord[a.severity] || 4) - (ord[b.severity] || 4);
      }
      return 0;
    });

  // Severity counts
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  hydratedVulns.forEach(v => { if (sevCounts[v.severity] !== undefined) sevCounts[v.severity]++; });

  // Status counts
  const statusCounts = {};
  hydratedVulns.forEach(v => { statusCounts[v.status] = (statusCounts[v.status] || 0) + 1; });

  const workflowCounts = hydratedVulns.reduce((acc, v) => {
    acc[v.workflowState] = (acc[v.workflowState] || 0) + 1;
    acc[v.slaState] = (acc[v.slaState] || 0) + 1;
    acc.unassigned += v.owner === 'Unassigned' ? 1 : 0;
    return acc;
  }, { Triage: 0, Ticketing: 0, Remediation: 0, Blocked: 0, Closed: 0, overdue: 0, 'due-soon': 0, healthy: 0, unassigned: 0 });

  const updateWorkflow = useCallback((findingId, patch) => {
    setWorkflowMeta(prev => ({
      ...prev,
      [findingId]: {
        ...(prev[findingId] || {}),
        ...patch,
      },
    }));
  }, []);

  // Toggle severity filter
  const toggleSev = (sev) => {
    setFilterSev(prev => {
      const next = new Set(prev);
      next.has(sev) ? next.delete(sev) : next.add(sev);
      return next;
    });
  };

  // Toggle checked
  const toggleCheck = (id) => {
    setChecked(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleCheckAll = () => {
    if (checked.size === displayVulns.length) {
      setChecked(new Set());
    } else {
      setChecked(new Set(displayVulns.map(v => v.id)));
    }
  };

  // Status update via PATCH
  const updateStatus = useCallback(async (findingId, newStatus) => {
    setStatusUpdating(findingId);
    // Optimistic update
    setVulns(prev => prev.map(v => v.id === findingId ? { ...v, status: newStatus } : v));
    try {
      await apiFetch(`/api/v1/findings/${findingId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
    } catch {}
    setStatusUpdating(null);
  }, []);

  // Re-test finding
  const retestFinding = useCallback(async (finding) => {
    const findingId = finding?.id;
    const target = String(finding?.target || finding?.url || '').trim();
    if (!findingId || !target) {
      setRetestError('This finding has no exact target metadata for retest.');
      return;
    }
    const moduleLabel = String(finding?.module || 'the persisted finding module');
    if (!window.confirm(
      `Confirm retesting finding ${findingId} with ${moduleLabel} against exact target ${target}?`
    )) return;
    setRetestError('');
    setRetesting(findingId);
    try {
      const confirmationBundle = await prepareActionConfirmations({
        intent: 'finding.retest',
        finding_id: findingId,
        scope: [target],
        exclude: [],
      });
      const res = await apiFetch(`/api/v1/findings/${encodeURIComponent(findingId)}/retest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(applyActionConfirmations({ dry_run: false }, confirmationBundle)),
      });
      if (res.ok) {
        const data = await res.json();
        setVulns(prev => prev.map(v => {
          if (v.id !== findingId) return v;
          return applyRetestTruth(v, data);
        }));
      } else {
        const data = await res.json().catch(() => ({}));
        setRetestError(dashboardErrorMessage(data, `Retest failed (${res.status})`));
      }
    } catch (error) {
      setRetestError(error instanceof Error ? error.message : 'Retest failed');
    }
    setRetesting(null);
  }, []);

  // Bulk status change
  const bulkStatusChange = useCallback(async (newStatus) => {
    const ids = [...checked];
    // Optimistic update first
    setVulns(prev => prev.map(v => ids.includes(v.id) ? { ...v, status: newStatus } : v));
    // Fire all PATCH requests in parallel
    await Promise.all(ids.map(id =>
      apiFetch(`/api/v1/findings/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      }).catch(() => {})
    ));
    setChecked(new Set());
  }, [checked]);

  // Bulk export
  const bulkExport = useCallback(() => {
    const ids = [...checked];
    const exportData = hydratedVulns.filter(v => ids.includes(v.id));
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forge_findings_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setChecked(new Set());
  }, [checked, hydratedVulns]);

  const bulkAssign = useCallback((owner) => {
    const ids = [...checked];
    setWorkflowMeta(prev => {
      const next = { ...prev };
      ids.forEach(id => {
        next[id] = { ...(next[id] || {}), owner, ticketState: owner === 'Unassigned' ? 'Not Filed' : 'Ready' };
      });
      return next;
    });
    setChecked(new Set());
  }, [checked]);

  const assignTicket = useCallback((v) => {
    updateWorkflow(v.id, {
      ticketState: v.ticketState === 'Not Filed' ? 'Ready' : v.ticketState,
      ticketId: v.ticketId || `APEX-${String(Date.now()).slice(-6)}`,
    });
  }, [updateWorkflow]);

  const generateTicketDraft = useCallback((v) => {
    const ticket = [
      `[${v.priority}] ${v.finding}`,
      `Target: ${v.target}`,
      `Owner: ${v.owner}`,
      `SLA: ${v.slaDays < 0 ? `${Math.abs(v.slaDays)} days overdue` : `${v.slaDays} days remaining`}`,
      `Severity: ${v.severity} | CVSS: ${v.cvss || '-'} | VPR: ${v.vpr || '-'}`,
      '',
      'Description:',
      v.description || '-',
      '',
      'Evidence:',
      v.evidence || '-',
      '',
      'Remediation:',
      v.remediation || '-',
    ].join('\n');
    navigator.clipboard?.writeText(ticket).catch(() => {});
    updateWorkflow(v.id, { ticketState: 'Filed', ticketId: v.ticketId || `APEX-${String(Date.now()).slice(-6)}` });
  }, [updateWorkflow]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Vulnerability Management"
        subtitle={`${vulns.length} findings across ${new Set(vulns.map(v => v.target)).size} targets`}
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={{ fontSize: '12px', padding: '4px 8px' }}>
              <option value="priority">Sort: Priority</option>
              <option value="sla">Sort: SLA</option>
              <option value="cvss">Sort: CVSS</option>
              <option value="vpr">Sort: VPR</option>
              <option value="severity">Sort: Severity</option>
            </select>
            <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: '12px', padding: '4px 8px' }}>
              <option value="all">All Statuses</option>
              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        }
      />

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', padding: '18px 32px', gap: '14px' }}>

        {/* LEFT: Filter Sidebar */}
        <div style={{ width: '200px', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <Card title="SEVERITY">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { label: 'Critical', key: 'critical', color: '#ff4444' },
                { label: 'High',     key: 'high',     color: '#ff8c00' },
                { label: 'Medium',   key: 'medium',   color: '#ffc400' },
                { label: 'Low',      key: 'low',      color: '#00d8f0' },
              ].map(s => (
                <label key={s.label} style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', fontSize: '13px' }}>
                  <input
                    type="checkbox"
                    checked={filterSev.has(s.key)}
                    onChange={() => toggleSev(s.key)}
                    style={{ accentColor: s.color }}
                  />
                  <span style={{ flex: 1 }}>{s.label}</span>
                  <span style={{ color: s.color, fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600 }}>{sevCounts[s.key]}</span>
                </label>
              ))}
            </div>
          </Card>

          <Card title="STATUS">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { label: 'Open',           color: '#ff4444' },
                { label: 'In Progress',    color: '#ffc400' },
                { label: 'Fixed',          color: '#00c853' },
                { label: 'Accepted',       color: '#2979ff' },
                { label: 'False Positive', color: '#7a8db0' },
              ].map(s => (
                <div key={s.label} style={{
                  display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px',
                  cursor: 'pointer', opacity: filterStatus === s.label || filterStatus === 'all' ? 1 : 0.4,
                }} onClick={() => setFilterStatus(filterStatus === s.label ? 'all' : s.label)}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: s.color, flexShrink: 0 }} />
                  <span style={{ flex: 1 }}>{s.label}</span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{statusCounts[s.label] || 0}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card title="TARGET">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {[...new Set(vulns.map(v => v.target))].map(t => (
                <div
                  key={t}
                  onClick={() => setFilterTarget(filterTarget === t ? 'all' : t)}
                  style={{
                    fontFamily: 'var(--font-mono)', fontSize: '12px', padding: '5px 8px',
                    borderRadius: '3px', cursor: 'pointer',
                    background: filterTarget === t ? 'rgba(229,57,53,0.10)' : 'transparent',
                    color: filterTarget === t ? 'var(--color-brand-red)' : 'var(--text-secondary)',
                    border: `1px solid ${filterTarget === t ? 'rgba(229,57,53,0.25)' : 'transparent'}`,
                    transition: 'all 0.15s',
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                  }}
                >{t}</div>
              ))}
              {filterTarget !== 'all' && (
                <button
                  onClick={() => setFilterTarget('all')}
                  style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', textAlign: 'left', padding: '2px 8px', marginTop: '2px' }}
                >× clear filter</button>
              )}
            </div>
          </Card>

          <Card title="OWNER">
            <select value={filterOwner} onChange={e => setFilterOwner(e.target.value)} style={{ width: '100%', fontSize: '12px' }}>
              <option value="all">All Owners</option>
              {OWNER_OPTIONS.map(owner => <option key={owner} value={owner}>{owner}</option>)}
            </select>
          </Card>

          <Card title="SLA">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                ['all', 'All', 'var(--text-muted)'],
                ['overdue', 'Overdue', 'var(--color-critical)'],
                ['due-soon', 'Due Soon', 'var(--color-medium)'],
                ['healthy', 'Healthy', 'var(--color-success)'],
              ].map(([key, label, color]) => (
                <button
                  key={key}
                  onClick={() => setFilterSla(key)}
                  style={{
                    textAlign: 'left',
                    padding: '6px 8px',
                    borderRadius: '3px',
                    border: `1px solid ${filterSla === key ? color : 'var(--border-color)'}`,
                    background: filterSla === key ? `${color}18` : 'transparent',
                    color: filterSla === key ? color : 'var(--text-secondary)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    cursor: 'pointer',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </Card>
        </div>

        {/* CENTER: Vuln Table */}
        <Card style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }} noPadding>
          <div style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border-color)',
            display: 'grid',
            gridTemplateColumns: 'repeat(5, minmax(110px, 1fr))',
            gap: '10px',
          }}>
            {[
              ['Triage', workflowCounts.Triage, 'var(--color-critical)'],
              ['Ticketing', workflowCounts.Ticketing, 'var(--color-medium)'],
              ['Remediation', workflowCounts.Remediation, 'var(--color-info)'],
              ['Blocked', workflowCounts.Blocked, 'var(--color-high)'],
              ['Closed', workflowCounts.Closed, 'var(--color-success)'],
            ].map(([label, value, color]) => (
              <div key={label} style={{ border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.015)', borderRadius: '4px', padding: '8px 10px' }}>
                <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{label}</div>
                <div className="font-heading" style={{ color, fontSize: '24px', fontWeight: 700, lineHeight: 1.1 }}>{value}</div>
              </div>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: '32px' }}>
                    <input
                      type="checkbox"
                      checked={checked.size > 0 && checked.size === displayVulns.length}
                      onChange={toggleCheckAll}
                      style={{ accentColor: 'var(--color-brand-red)' }}
                    />
                  </th>
                  <th>CVE ID</th>
                  <th>Finding</th>
                  <th>Target</th>
                  <th>Priority</th>
                  <th>Owner</th>
                  <th>SLA</th>
                  <th>CVSS</th>
                  <th>VPR</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Verification / Proof</th>
                  <th>Retest</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {displayVulns.map(v => (
                  <tr
                    key={v.id}
                    onClick={() => { setSelectedId(v.id); }}
                    style={{
                      cursor: 'pointer',
                      backgroundColor: selectedId === v.id ? 'rgba(229,57,53,0.06)' : checked.has(v.id) ? 'rgba(41,121,255,0.04)' : undefined,
                      transition: 'background-color 0.15s',
                    }}
                  >
                    <td onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={checked.has(v.id)}
                        onChange={() => toggleCheck(v.id)}
                        style={{ accentColor: 'var(--color-brand-red)' }}
                      />
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--color-info)' }}>{v.cve || '—'}</td>
                    <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.finding}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{v.target}</td>
                    <td><Badge severity={v.priority === 'P0' || v.priority === 'P1' ? 'critical' : v.priority === 'P2' ? 'high' : 'info'}>{v.priority}</Badge></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: v.owner === 'Unassigned' ? 'var(--color-medium)' : 'var(--text-secondary)' }}>{v.owner}</td>
                    <td>
                      <span className="font-mono" style={{
                        fontSize: '11px',
                        color: v.slaState === 'overdue' ? 'var(--color-critical)' : v.slaState === 'due-soon' ? 'var(--color-medium)' : 'var(--color-success)',
                      }}>
                        {v.slaDays < 0 ? `${Math.abs(v.slaDays)}d overdue` : `${v.slaDays}d left`}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontWeight: 700,
                        color: v.cvss >= 9 ? '#ff4444' : v.cvss >= 7 ? '#ff8c00' : v.cvss >= 4 ? '#ffc400' : 'var(--text-muted)',
                      }}>{v.cvss}</span>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '12px',
                        color: (v.vpr || 0) >= 8 ? '#ff4444' : (v.vpr || 0) >= 5 ? '#ff8c00' : 'var(--text-muted)',
                      }}>{v.vpr || '—'}</span>
                    </td>
                    <td><Badge severity={v.severity}>{v.severity}</Badge></td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 600,
                        color: confidenceColor[v.confidence] || 'var(--text-muted)',
                        textTransform: 'uppercase',
                      }}>{v.confidence || 'UNVERIFIED'}</span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '10px' }}>
                      <div>{v.verification_state || 'unknown'}</div>
                      <div style={{ color: 'var(--text-muted)' }}>{v.proof_type || 'unknown'} / {v.maturity || 'experimental'}</div>
                    </td>
                    <td className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{v.retest_status || 'not_retested'}</td>
                    <td><Badge severity={statusBadge(v.status)}>{v.status}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Bulk Operations Bar */}
          {checked.size > 0 && (
            <div style={{
              padding: '10px 16px',
              borderTop: '1px solid var(--border-color)',
              background: 'rgba(41,121,255,0.06)',
              display: 'flex', alignItems: 'center', gap: '12px',
              animation: 'fadeIn 0.2s ease',
            }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--color-info)', fontWeight: 600 }}>
                {checked.size} selected
              </span>
              <div style={{ width: '1px', height: '16px', background: 'var(--border-color)' }} />
              <select
                value={bulkAction}
                onChange={e => { bulkStatusChange(e.target.value); setBulkAction(''); }}
                style={{ fontSize: '12px', padding: '4px 8px' }}
              >
                <option value="">Change Status…</option>
                {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select
                value=""
                onChange={e => { if (e.target.value) bulkAssign(e.target.value); }}
                style={{ fontSize: '12px', padding: '4px 8px' }}
              >
                <option value="">Assign Owner…</option>
                {OWNER_OPTIONS.map(owner => <option key={owner} value={owner}>{owner}</option>)}
              </select>
              <Button variant="secondary" style={{ padding: '4px 12px', fontSize: '11px' }} onClick={bulkExport}>
                Export JSON
              </Button>
              <div style={{ flex: 1 }} />
              <button
                onClick={() => setChecked(new Set())}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '12px', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
              >Clear Selection</button>
            </div>
          )}
        </Card>

        {/* RIGHT: Slide-Out Detail Panel */}
        {selected && (
          <div
            ref={panelRef}
            style={{
              width: '40%', minWidth: '360px', maxWidth: '520px',
              flexShrink: 0,
              display: 'flex', flexDirection: 'column', gap: '0',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '4px',
              animation: 'slideInRight 0.25s ease',
              overflow: 'hidden',
            }}
          >
            {/* Panel Header */}
            <div style={{
              padding: '16px 20px', borderBottom: '1px solid var(--border-color)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
            }}>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--color-info)', marginBottom: '4px' }}>{selected.cve || 'No CVE'}</div>
                <div style={{ fontFamily: 'var(--font-heading)', fontSize: '18px', fontWeight: 700, lineHeight: 1.3 }}>{selected.finding}</div>
              </div>
              <button
                onClick={() => setSelectedId(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '20px', padding: '0 4px', lineHeight: 1 }}
              >×</button>
            </div>

            {/* Panel Body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>

              {/* Score Row */}
              <div style={{ display: 'flex', gap: '12px' }}>
                <ScoreBox label="PRIORITY" value={selected.priority} color={selected.priority === 'P0' || selected.priority === 'P1' ? 'var(--color-critical)' : 'var(--color-high)'} />
                <ScoreBox label="SEVERITY" value={selected.severity.toUpperCase()} color={severityColor[selected.severity]} />
                <ScoreBox label="CVSS" value={selected.cvss} color={selected.cvss >= 9 ? '#ff4444' : selected.cvss >= 7 ? '#ff8c00' : '#ffc400'} />
                <ScoreBox label="SLA" value={selected.slaDays < 0 ? `${Math.abs(selected.slaDays)}D LATE` : `${selected.slaDays}D`} color={selected.slaState === 'overdue' ? 'var(--color-critical)' : selected.slaState === 'due-soon' ? 'var(--color-medium)' : 'var(--color-success)'} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                <div>Verification: <strong>{selected.verification_state || 'unknown'}</strong></div>
                <div>Proof: <strong>{selected.proof_type || 'unknown'}</strong></div>
                <div>Maturity: <strong>{selected.maturity || 'experimental'}</strong></div>
                <div>Confidence: <strong>{selected.confidence || 'UNVERIFIED'}</strong></div>
                <div>Retest: <strong>{selected.retest_status || 'not_retested'}</strong></div>
                <div>Workflow: <strong>{selected.status || 'open'}</strong></div>
              </div>

              {/* Status Editor */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Status</span>
                <div style={{ display: 'flex', gap: '6px', flex: 1, flexWrap: 'wrap' }}>
                  {STATUS_OPTIONS.map(s => (
                    <button
                      key={s}
                      onClick={() => updateStatus(selected.id, s)}
                      disabled={statusUpdating === selected.id}
                      style={{
                        padding: '4px 10px', borderRadius: '3px', fontSize: '11px',
                        fontFamily: 'var(--font-mono)', cursor: 'pointer',
                        border: `1px solid ${selected.status === s ? 'var(--color-brand-red)' : 'var(--border-color)'}`,
                        background: selected.status === s ? 'rgba(229,57,53,0.12)' : 'transparent',
                        color: selected.status === s ? 'var(--color-brand-red)' : 'var(--text-secondary)',
                        transition: 'all 0.15s',
                        opacity: statusUpdating === selected.id ? 0.5 : 1,
                      }}
                    >{s}</button>
                  ))}
                </div>
              </div>

              {/* Workflow Editor */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                gap: '10px',
                padding: '12px',
                border: '1px solid var(--border-color)',
                background: 'rgba(255,255,255,0.015)',
                borderRadius: '4px',
              }}>
                <WorkflowField label="Owner">
                  <select value={selected.owner} onChange={e => updateWorkflow(selected.id, { owner: e.target.value, ticketState: e.target.value === 'Unassigned' ? 'Not Filed' : 'Ready' })}>
                    {OWNER_OPTIONS.map(owner => <option key={owner} value={owner}>{owner}</option>)}
                  </select>
                </WorkflowField>
                <WorkflowField label="Business Impact">
                  <select value={selected.businessImpact} onChange={e => updateWorkflow(selected.id, { businessImpact: e.target.value })}>
                    {BUSINESS_OPTIONS.map(impact => <option key={impact} value={impact}>{impact}</option>)}
                  </select>
                </WorkflowField>
                <WorkflowField label="Due Date">
                  <input type="date" value={selected.dueDate} onChange={e => updateWorkflow(selected.id, { dueDate: e.target.value })} />
                </WorkflowField>
                <WorkflowField label="Ticket State">
                  <select value={selected.ticketState} onChange={e => updateWorkflow(selected.id, { ticketState: e.target.value })}>
                    {TICKET_STATES.map(state => <option key={state} value={state}>{state}</option>)}
                  </select>
                </WorkflowField>
                <WorkflowField label="Ticket ID">
                  <input value={selected.ticketId} placeholder="JIRA-1234" onChange={e => updateWorkflow(selected.id, { ticketId: e.target.value })} />
                </WorkflowField>
                <WorkflowField label="Queue State">
                  <input value={selected.workflowState} readOnly style={{ color: 'var(--text-muted)' }} />
                </WorkflowField>
                <div style={{ gridColumn: '1 / -1' }}>
                  <WorkflowField label="Handoff Note">
                    <textarea
                      value={selected.queueNote}
                      onChange={e => updateWorkflow(selected.id, { queueNote: e.target.value })}
                      placeholder="Ownership context, compensating controls, rollback window..."
                      rows={3}
                      style={{
                        width: '100%',
                        resize: 'vertical',
                        backgroundColor: 'var(--bg-input)',
                        border: '1px solid var(--border-color)',
                        color: 'var(--text-primary)',
                        borderRadius: '4px',
                        padding: '8px 12px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                      }}
                    />
                  </WorkflowField>
                </div>
              </div>

              {/* Detail Rows */}
              <DetailSection title="Description" content={selected.description} />
              <DetailSection title="Reproduction Steps" content={selected.repro} mono />
              <DetailSection title="Evidence" content={selected.evidence} mono />
              <DetailSection title="Remediation" content={selected.remediation} />

              {/* Metadata */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px' }}>
                {[
                  { label: 'Target', value: selected.target },
                  { label: 'Module', value: selected.module },
                  { label: 'Owner', value: selected.owner },
                  { label: 'Business Impact', value: selected.businessImpact },
                  { label: 'Ticket', value: selected.ticketId || selected.ticketState },
                  { label: 'Attack Vector', value: 'Network' },
                  { label: 'Complexity', value: selected.cvss >= 9 ? 'Low' : 'Medium' },
                  { label: 'Privileges Required', value: selected.cvss >= 9 ? 'None' : 'Low' },
                ].map(row => (
                  <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '6px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{row.value || '—'}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel Footer */}
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-color)', display: 'flex', gap: '8px' }}>
              <Button
                variant="primary"
                style={{ flex: 1, fontSize: '12px', padding: '8px 12px' }}
                onClick={() => retestFinding(selected)}
                disabled={retesting === selected.id}
              >
                {retesting === selected.id ? (
                  <>
                    <svg viewBox="0 0 24 24" style={{ width: 14, height: 14, animation: 'spin 1s linear infinite' }}>
                      <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="32" strokeLinecap="round" />
                    </svg>
                    Re-testing…
                  </>
                ) : 'Re-test'}
              </Button>
              <Button variant="secondary" style={{ flex: 1, fontSize: '12px', padding: '8px 12px' }} onClick={() => assignTicket(selected)}>
                Assign Ticket
              </Button>
              <Button variant="secondary" style={{ flex: 1, fontSize: '12px', padding: '8px 12px' }} onClick={() => generateTicketDraft(selected)}>
                Copy Ticket
              </Button>
            </div>
            {retestError && (
              <div style={{ padding: '0 20px 12px', color: 'var(--color-critical)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {retestError}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

/* ── Helper Components ── */

function ScoreBox({ label, value, color }) {
  return (
    <div style={{
      flex: 1, textAlign: 'center', padding: '10px 6px',
      background: 'var(--bg-input)', borderRadius: '4px',
      border: '1px solid var(--border-color)',
    }}>
      <div style={{ fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-dimmed)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>{label}</div>
      <div style={{ fontSize: '16px', fontFamily: 'var(--font-heading)', fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
    </div>
  );
}

function DetailSection({ title, content, mono = false }) {
  if (!content) return null;
  return (
    <div>
      <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dimmed)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>{title}</div>
      <div style={{
        fontSize: '12px', lineHeight: 1.7,
        color: 'var(--text-secondary)',
        fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)',
        whiteSpace: 'pre-wrap',
        background: mono ? 'rgba(255,68,68,0.03)' : 'transparent',
        padding: mono ? '10px 12px' : '0',
        borderRadius: mono ? '4px' : '0',
        border: mono ? '1px solid rgba(255,68,68,0.08)' : 'none',
      }}>{content}</div>
    </div>
  );
}

function WorkflowField({ label, children }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
      <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dimmed)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</span>
      {children}
    </label>
  );
}

export default Vulnerabilities;
