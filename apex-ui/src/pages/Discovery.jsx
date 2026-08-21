import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { Server, Activity, Layers, AlertTriangle } from 'lucide-react';

const Discovery = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar 
        title="Network Reconnaissance & Asset Discovery" 
        subtitle="Host enumeration, port scanning, service fingerprinting, OS detection"
        actions={
          <>
            <Button variant="secondary">EXPORT</Button>
            <Button variant="primary">SCAN NETWORK</Button>
          </>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>
        {/* ROW 1: Input Bar */}
        <div style={{ display: 'flex', gap: '12px' }}>
          <input 
            type="text" 
            defaultValue="" 
            placeholder="Enter CIDR range or hostname..."
            style={{ flex: 1, height: '40px' }} 
          />
          <select style={{ height: '40px', width: '200px' }}>
            <option>Top 1000 Ports</option>
            <option>All 65535 Ports</option>
          </select>
          <Button variant="primary">SCAN NETWORK</Button>
        </div>

        {/* ROW 2: Stat Cards */}
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'HOSTS ONLINE', value: '0', color: 'var(--color-success)', icon: Server, sparkline: [] },
            { label: 'OPEN PORTS', value: '0', color: 'var(--color-info)', icon: Activity, sparkline: [] },
            { label: 'SERVICES', value: '0', color: 'var(--color-medium)', icon: Layers, sparkline: [] },
            { label: 'POTENTIAL VULNS', value: '0', color: 'var(--color-critical)', icon: AlertTriangle, sparkline: [] }
          ].map(stat => (
            <Card key={stat.label} style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div className="font-mono text-muted" style={{ fontSize: '10px' }}>{stat.label}</div>
                  <div className="font-heading" style={{ fontSize: '32px', fontWeight: 600, color: stat.color, marginTop: '4px' }}>{stat.value}</div>
                </div>
                <div style={{ padding: '8px', borderRadius: '8px', backgroundColor: 'var(--bg-input)' }}>
                  <stat.icon size={20} color={stat.color} />
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end', height: '24px', gap: '2px', marginTop: '12px' }}>
                {stat.sparkline.map((val, i) => (
                  <div key={i} style={{ 
                    flex: 1, 
                    backgroundColor: stat.color, 
                    height: `${val}%`,
                    opacity: 0.3 + (i * 0.1)
                  }}></div>
                ))}
              </div>
            </Card>
          ))}
        </div>

        {/* ROW 3: Host Table */}
        <Card title="Discovered Hosts" headerRight={
          <div style={{ display: 'flex', gap: '8px' }}>
            <Button variant="secondary" style={{ padding: '4px 8px', fontSize: '12px' }}>Export CSV</Button>
            <Button variant="secondary" style={{ padding: '4px 8px', fontSize: '12px' }}>Add to Targets</Button>
          </div>
        } style={{ flex: 1 }} noPadding>
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>OS / Fingerprint</th>
                <th>Open Ports</th>
                <th>Services</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                  No hosts discovered — run a network scan to begin
                </td>
              </tr>
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
};

export default Discovery;
