import React, { useState } from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Badge from '../components/Badge';

const policies = [
  { name: 'OWASP Top 10 2021', dotColor: '#e53935', status: 'Draft' },
  { name: 'PCI-DSS v4.0', dotColor: '#2979ff', status: 'Draft' },
  { name: 'ISO 27001:2022', dotColor: '#ffc400', status: 'Draft' },
  { name: 'NIST CSF 2.0', dotColor: '#00d8f0', status: 'Draft' },
  { name: 'Custom Exclusions', dotColor: '#00c853', status: 'Draft' },
];

const owaspCategories = [
  { id: 'A01', name: 'Broken Access Control', pct: 0, color: 'var(--text-muted)' },
  { id: 'A02', name: 'Cryptographic Failures', pct: 0, color: 'var(--text-muted)' },
  { id: 'A03', name: 'Injection', pct: 0, color: 'var(--text-muted)' },
  { id: 'A04', name: 'Insecure Design', pct: 0, color: 'var(--text-muted)' },
  { id: 'A05', name: 'Security Misconfiguration', pct: 0, color: 'var(--text-muted)' },
  { id: 'A06', name: 'Vulnerable Components', pct: 0, color: 'var(--text-muted)' },
  { id: 'A07', name: 'Auth Failures', pct: 0, color: 'var(--text-muted)' },
  { id: 'A08', name: 'Integrity Failures', pct: 0, color: 'var(--text-muted)' },
  { id: 'A09', name: 'Logging Failures', pct: 0, color: 'var(--text-muted)' },
  { id: 'A10', name: 'SSRF', pct: 0, color: 'var(--text-muted)' },
];

const Policies = () => {
  const [selected, setSelected] = useState(policies[0]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar title="Security Policies & Compliance" />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', padding: '18px 32px', gap: '14px' }}>

        {/* LEFT: Policy List */}
        <div style={{ width: '300px', flexShrink: 0 }}>
          <Card noPadding style={{ height: '100%' }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)' }}>
              <span style={{ fontSize: '13px', fontWeight: 500 }}>Policy Library</span>
            </div>
            {policies.map(p => (
              <div
                key={p.name}
                onClick={() => setSelected(p)}
                style={{
                  display: 'flex', alignItems: 'center', gap: '12px',
                  padding: '14px 16px',
                  borderBottom: '1px solid var(--border-color)',
                  cursor: 'pointer',
                  backgroundColor: selected?.name === p.name ? 'rgba(229,57,53,0.06)' : 'transparent',
                  borderLeft: selected?.name === p.name ? '2px solid var(--color-brand-red)' : '2px solid transparent',
                }}
              >
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: p.dotColor, flexShrink: 0 }} />
                <div style={{ flex: 1, fontSize: '13px', fontWeight: selected?.name === p.name ? 500 : 400 }}>{p.name}</div>
                <Badge severity={p.status === 'Active' ? 'active' : 'medium'}>{p.status}</Badge>
              </div>
            ))}
          </Card>
        </div>

        {/* RIGHT: Detail View */}
        <div style={{ flex: 1, display: 'flex', gap: '14px', overflow: 'auto' }}>
          {selected?.name === 'OWASP Top 10 2021' ? (
            <>
              <Card title="Category Compliance" style={{ flex: 1 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {owaspCategories.map(cat => (
                    <div key={cat.id}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {cat.id} <span style={{ color: 'var(--text-muted)' }}>{cat.name}</span>
                        </span>
                        <span style={{ color: cat.color, fontWeight: 600 }}>{cat.pct}%</span>
                      </div>
                      <div style={{ height: '4px', backgroundColor: 'var(--bg-input)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div style={{ width: `${cat.pct}%`, height: '100%', backgroundColor: cat.color, borderRadius: '2px' }} />
                      </div>
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Policy Settings" style={{ width: '280px', flexShrink: 0 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {[
                    ['Version', 'OWASP Top 10 2021'],
                    ['Last Updated', '—'],
                    ['Scan Profile', '—'],
                    ['Auto-Remediate', 'Disabled'],
                    ['SLA — Critical', '—'],
                    ['SLA — High', '—'],
                    ['SLA — Medium', '—'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px', fontSize: '12px' }}>
                      <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{v}</span>
                    </div>
                  ))}
                  <div style={{ marginTop: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '1px' }}>
                      Exclusion Patterns
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)',
                      padding: '8px', backgroundColor: 'var(--bg-input)',
                      borderRadius: '3px',
                    }}>No exclusions configured</div>
                  </div>
                </div>
              </Card>
            </>
          ) : (
            <Card style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '200px', color: 'var(--text-muted)', flexDirection: 'column', gap: '12px' }}>
                <div style={{ fontSize: '16px' }}>{selected?.name}</div>
                <Badge severity={selected?.status === 'Active' ? 'active' : 'medium'}>{selected?.status}</Badge>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default Policies;
