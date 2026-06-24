import React, { useState, useRef, useCallback } from 'react';
import { apiFetch } from '../config/api';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import {
  Upload, FileText, Shield, AlertTriangle, ChevronDown,
  ChevronRight, Lock, Key, Eye, Trash2, Download,
} from 'lucide-react';

const PROFILES = [
  { value: 'defensive', label: 'Defensive Triage', desc: 'Identify, classify, and prioritize credential exposure for rotation' },
  { value: 'red_team',  label: 'Red Team Simulation', desc: 'Map attack paths from exposed material without executing' },
];

const RISK_COLORS = {
  critical: 'var(--color-critical)',
  high:     'var(--color-high)',
  medium:   'var(--color-medium)',
  low:      'var(--color-low)',
  none:     'var(--text-muted)',
};

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ─── Styled sub-components ───────────────────────────────────────────

function DropZone({ onFile, disabled }) {
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef(null);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    if (disabled) return;
    const f = e.dataTransfer?.files?.[0];
    if (f) onFile(f);
  }, [onFile, disabled]);

  return (
    <div
      onDragOver={e => { e.preventDefault(); if (!disabled) setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !disabled && fileRef.current?.click()}
      style={{
        border: `2px dashed ${dragging ? 'var(--color-brand-red)' : 'var(--border-color)'}`,
        borderRadius: '8px',
        padding: '48px 24px',
        textAlign: 'center',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'all 0.25s ease',
        background: dragging ? 'rgba(229,57,53,0.04)' : 'transparent',
      }}
    >
      <Upload size={32} color={dragging ? 'var(--color-brand-red)' : 'var(--text-dimmed)'} style={{ marginBottom: '12px' }} />
      <div style={{ fontFamily: 'var(--font-heading)', fontSize: '14px', marginBottom: '6px' }}>
        Drop credential file here
      </div>
      <div className="text-muted" style={{ fontSize: '12px' }}>
        CSV · TSV · TXT · JSON · DOCX · XLSX — max 8 MB
      </div>
      <input
        ref={fileRef}
        type="file"
        accept=".csv,.tsv,.txt,.md,.log,.json,.docx,.xlsx,.doc,.xls,.note,.notes"
        style={{ display: 'none' }}
        onChange={e => { if (e.target.files?.[0]) onFile(e.target.files[0]); }}
      />
    </div>
  );
}

function RiskDot({ risk }) {
  return (
    <span style={{
      width: '8px', height: '8px', borderRadius: '50%',
      background: RISK_COLORS[risk] || RISK_COLORS.medium,
      display: 'inline-block', flexShrink: 0,
    }} />
  );
}

function ExposureRow({ exp, idx }) {
  const [open, setOpen] = useState(false);
  const Arrow = open ? ChevronDown : ChevronRight;

  return (
    <div style={{
      borderBottom: '1px solid var(--border-color)',
      padding: '0',
    }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex', alignItems: 'center', gap: '12px',
          padding: '12px 16px', cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <Arrow size={14} color="var(--text-dimmed)" />
        <RiskDot risk={exp.risk} />
        <span className="font-mono" style={{ fontSize: '12px', color: RISK_COLORS[exp.risk], minWidth: '64px', textTransform: 'uppercase' }}>
          {exp.risk}
        </span>
        <span style={{ fontSize: '13px', fontWeight: 500, flex: 1 }}>{exp.kind}</span>
        <span className="font-mono text-muted" style={{ fontSize: '12px' }}>
          {exp.account || '—'}
        </span>
        <span className="font-mono text-muted" style={{ fontSize: '11px', opacity: 0.6 }}>
          {exp.source}
        </span>
      </div>
      {open && (
        <div style={{
          padding: '12px 16px 16px 44px',
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 24px',
          fontSize: '12px', background: 'rgba(0,0,0,0.15)',
        }}>
          <div>
            <span className="text-muted">Masked Secret</span>
            <div className="font-mono" style={{ marginTop: '2px', wordBreak: 'break-all' }}>{exp.secret_mask || '—'}</div>
          </div>
          <div>
            <span className="text-muted">Fingerprint</span>
            <div className="font-mono" style={{ marginTop: '2px' }}>{exp.secret_fingerprint || '—'}</div>
          </div>
          <div>
            <span className="text-muted">Score</span>
            <div className="font-mono" style={{ marginTop: '2px' }}>{exp.score}/100</div>
          </div>
          <div>
            <span className="text-muted">Indicators</span>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
              {(exp.indicators || []).map((ind, i) => (
                <Badge key={i} variant="neutral">{ind.replace(/_/g, ' ')}</Badge>
              ))}
              {!(exp.indicators?.length) && <span className="text-muted">none</span>}
            </div>
          </div>
          {exp.context && (
            <div style={{ gridColumn: '1 / -1' }}>
              <span className="text-muted">Context</span>
              <pre className="font-mono" style={{
                marginTop: '4px', fontSize: '11px', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                background: 'rgba(0,0,0,0.2)', padding: '8px', borderRadius: '4px', maxHeight: '120px', overflow: 'auto',
              }}>
                {exp.context}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AttackPathCard({ path, idx }) {
  const [open, setOpen] = useState(false);
  const Arrow = open ? ChevronDown : ChevronRight;

  return (
    <div style={{
      border: '1px solid var(--border-color)',
      borderRadius: '6px', marginBottom: '8px',
      background: 'var(--bg-card)',
    }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex', alignItems: 'center', gap: '10px',
          padding: '12px 14px', cursor: 'pointer',
        }}
      >
        <Arrow size={14} color="var(--text-dimmed)" />
        <Shield size={14} color={RISK_COLORS[path.severity] || 'var(--text-muted)'} />
        <span style={{ fontSize: '13px', fontWeight: 500, flex: 1 }}>
          {path.type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
        </span>
        <Badge variant={path.severity === 'critical' ? 'critical' : path.severity === 'high' ? 'high' : 'neutral'}>
          {path.severity}
        </Badge>
      </div>
      {open && (
        <div style={{ padding: '0 14px 14px 40px', fontSize: '12px' }}>
          <div className="text-muted" style={{ marginBottom: '6px' }}>
            Source: <span className="font-mono">{path.source_account}</span> via {path.starting_material}
          </div>
          <div style={{ marginBottom: '8px' }}>
            <strong style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Simulation Steps</strong>
            <ol style={{ margin: '4px 0 0 16px', padding: 0, lineHeight: 1.8 }}>
              {(path.simulation || []).map((step, i) => <li key={i}>{step}</li>)}
            </ol>
          </div>
          <div>
            <strong style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Controls to Validate</strong>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
              {(path.likely_controls_to_validate || []).map((ctrl, i) => (
                <Badge key={i} variant="neutral">{ctrl}</Badge>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main page component ─────────────────────────────────────────────

export default function CredentialAnalysis({ authToken }) {
  const [file, setFile]           = useState(null);
  const [profile, setProfile]     = useState('defensive');
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');
  const [result, setResult]       = useState(null);
  const [riskFilter, setRiskFilter] = useState('all');
  const [tab, setTab]             = useState('exposures');

  const handleFile = useCallback((f) => {
    setFile(f);
    setResult(null);
    setError('');
  }, []);

  const analyze = useCallback(async () => {
    if (!file) return;
    setLoading(true);
    setError('');
    try {
      const buf = await file.arrayBuffer();
      const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
      const res = await apiFetch('/api/v1/credentials/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, content_base64: b64, profile }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `HTTP ${res.status}`);
      }
      setResult(await res.json());
      setTab('exposures');
      setRiskFilter('all');
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  }, [file, profile]);

  const clear = () => { setFile(null); setResult(null); setError(''); };

  const filteredExposures = result?.exposures?.filter(
    e => riskFilter === 'all' || e.risk === riskFilter
  ) || [];

  const summary = result?.summary || {};

  return (
    <div style={{ padding: '32px', maxWidth: '1200px' }}>
      {/* Header */}
      <div style={{ marginBottom: '28px' }}>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '22px', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Key size={20} color="var(--color-brand-red)" />
          Credential Exposure Analysis
        </h2>
        <p className="text-muted" style={{ fontSize: '13px', marginTop: '6px' }}>
          Upload credential dumps, password files, or configuration exports for safe exposure triage. Secrets are masked and never replayed.
        </p>
      </div>

      {/* Upload + Controls */}
      {!result && (
        <Card style={{ marginBottom: '20px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <DropZone onFile={handleFile} disabled={loading} />

            {file && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: '12px',
                padding: '12px 16px', borderRadius: '6px',
                background: 'rgba(229,57,53,0.06)', border: '1px solid rgba(229,57,53,0.15)',
              }}>
                <FileText size={18} color="var(--color-brand-red)" />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '13px', fontWeight: 500 }}>{file.name}</div>
                  <div className="text-muted font-mono" style={{ fontSize: '11px' }}>
                    {(file.size / 1024).toFixed(1)} KB
                  </div>
                </div>
                <button onClick={clear} style={{
                  background: 'none', border: 'none', cursor: 'pointer', padding: '4px',
                }}>
                  <Trash2 size={14} color="var(--text-dimmed)" />
                </button>
              </div>
            )}

            {/* Profile picker */}
            <div>
              <label className="font-mono text-muted" style={{ fontSize: '10px', textTransform: 'uppercase', display: 'block', marginBottom: '8px' }}>
                Analysis Profile
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                {PROFILES.map(p => (
                  <div
                    key={p.value}
                    onClick={() => setProfile(p.value)}
                    style={{
                      flex: 1, padding: '12px 14px', borderRadius: '6px', cursor: 'pointer',
                      border: `1px solid ${profile === p.value ? 'var(--color-brand-red)' : 'var(--border-color)'}`,
                      background: profile === p.value ? 'rgba(229,57,53,0.06)' : 'transparent',
                      transition: 'all 0.2s',
                    }}
                  >
                    <div style={{ fontSize: '13px', fontWeight: 500, marginBottom: '2px' }}>{p.label}</div>
                    <div className="text-muted" style={{ fontSize: '11px' }}>{p.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {error && (
              <div className="font-mono" style={{ color: 'var(--color-critical)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={14} /> {error}
              </div>
            )}

            <Button variant="primary" onClick={analyze} disabled={!file || loading} fullWidth>
              {loading ? 'ANALYZING…' : 'ANALYZE EXPOSURE'}
            </Button>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Summary cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '20px' }}>
            {[
              { label: 'Records Scanned', value: summary.records_scanned, icon: Eye },
              { label: 'Exposures Found', value: summary.exposures_found, icon: AlertTriangle, color: summary.exposures_found ? RISK_COLORS[summary.highest_risk] : undefined },
              { label: 'Attack Paths',    value: result.paths?.length || 0, icon: Shield },
              { label: 'Highest Risk',    value: (summary.highest_risk || 'none').toUpperCase(), icon: Lock, color: RISK_COLORS[summary.highest_risk] },
            ].map((card, i) => (
              <Card key={i} style={{ padding: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <card.icon size={14} color={card.color || 'var(--text-muted)'} />
                  <span className="font-mono text-muted" style={{ fontSize: '10px', textTransform: 'uppercase' }}>{card.label}</span>
                </div>
                <div style={{ fontSize: '24px', fontFamily: 'var(--font-heading)', fontWeight: 700, color: card.color || 'var(--text-primary)' }}>
                  {card.value}
                </div>
              </Card>
            ))}
          </div>

          {/* Safety banner */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 16px',
            borderRadius: '6px', marginBottom: '20px', fontSize: '12px',
            background: 'rgba(46,125,50,0.08)', border: '1px solid rgba(46,125,50,0.2)', color: 'rgb(129,199,132)',
          }}>
            <Lock size={14} />
            <span>Simulation only — no live authentication attempted, no raw secrets returned, no attacks executed.</span>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
            {[
              { id: 'exposures', label: `Exposures (${result.exposures?.length || 0})` },
              { id: 'paths',     label: `Attack Paths (${result.paths?.length || 0})` },
              { id: 'remediation', label: 'Remediation' },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  padding: '8px 16px', fontSize: '12px', fontFamily: 'var(--font-mono)',
                  background: tab === t.id ? 'rgba(229,57,53,0.1)' : 'transparent',
                  border: `1px solid ${tab === t.id ? 'var(--color-brand-red)' : 'var(--border-color)'}`,
                  borderRadius: '4px', cursor: 'pointer',
                  color: tab === t.id ? 'var(--color-brand-red)' : 'var(--text-muted)',
                  transition: 'all 0.2s',
                }}
              >
                {t.label}
              </button>
            ))}

            <div style={{ flex: 1 }} />
            <Button variant="secondary" onClick={clear} style={{ fontSize: '12px' }}>
              NEW ANALYSIS
            </Button>
          </div>

          {/* Tab: Exposures */}
          {tab === 'exposures' && (
            <Card style={{ padding: 0, overflow: 'hidden' }}>
              {/* Risk filter bar */}
              <div style={{
                display: 'flex', gap: '6px', padding: '12px 16px',
                borderBottom: '1px solid var(--border-color)', alignItems: 'center',
              }}>
                <span className="font-mono text-muted" style={{ fontSize: '10px', textTransform: 'uppercase', marginRight: '8px' }}>Filter:</span>
                {['all', 'critical', 'high', 'medium', 'low'].map(r => (
                  <button
                    key={r}
                    onClick={() => setRiskFilter(r)}
                    style={{
                      padding: '3px 10px', fontSize: '11px', borderRadius: '3px',
                      border: `1px solid ${riskFilter === r ? (RISK_COLORS[r] || 'var(--color-brand-red)') : 'var(--border-color)'}`,
                      background: riskFilter === r ? 'rgba(255,255,255,0.04)' : 'transparent',
                      color: riskFilter === r ? (RISK_COLORS[r] || 'var(--text-primary)') : 'var(--text-dimmed)',
                      cursor: 'pointer', textTransform: 'uppercase', fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {r} {r !== 'all' && summary.by_risk?.[r] ? `(${summary.by_risk[r]})` : ''}
                  </button>
                ))}
              </div>

              {filteredExposures.length === 0 ? (
                <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                  {result.exposures?.length ? 'No exposures match this filter.' : 'No credential-like material detected.'}
                </div>
              ) : (
                filteredExposures.map((exp, i) => <ExposureRow key={i} exp={exp} idx={i} />)
              )}
            </Card>
          )}

          {/* Tab: Attack Paths */}
          {tab === 'paths' && (
            <div>
              {(result.paths || []).length === 0 ? (
                <Card>
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                    No simulated attack paths generated from the exposed material.
                  </div>
                </Card>
              ) : (
                (result.paths || []).map((p, i) => <AttackPathCard key={i} path={p} idx={i} />)
              )}
            </div>
          )}

          {/* Tab: Remediation */}
          {tab === 'remediation' && (
            <Card>
              <div style={{ fontSize: '14px', fontFamily: 'var(--font-heading)', fontWeight: 600, marginBottom: '16px' }}>
                Remediation Plan
              </div>
              <ol style={{ margin: 0, paddingLeft: '20px', lineHeight: 2.0, fontSize: '13px' }}>
                {(result.remediation || []).map((step, i) => (
                  <li key={i} style={{ paddingLeft: '4px' }}>{step}</li>
                ))}
              </ol>

              {result.extraction_notes?.length > 0 && (
                <div style={{ marginTop: '20px', padding: '12px', borderRadius: '6px', background: 'rgba(255,167,38,0.08)', border: '1px solid rgba(255,167,38,0.15)' }}>
                  <div className="font-mono" style={{ fontSize: '10px', textTransform: 'uppercase', color: 'rgba(255,167,38,0.8)', marginBottom: '6px' }}>
                    Extraction Notes
                  </div>
                  {result.extraction_notes.map((n, i) => (
                    <div key={i} className="text-muted" style={{ fontSize: '12px', marginBottom: '2px' }}>• {n}</div>
                  ))}
                </div>
              )}
            </Card>
          )}
        </>
      )}
    </div>
  );
}
