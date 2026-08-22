import React from 'react';
import Button from './Button';
import { Users } from 'lucide-react';

const TopBar = ({ title, subtitle = null, actions = null }) => {
  return (
    <div style={{
      padding: '20px 32px',
      borderBottom: '1px solid var(--border-color)',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      flexShrink: 0
    }}>
      <div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <h2 style={{ fontSize: '32px', fontWeight: 700, margin: '0 0 4px 0', letterSpacing: '0.5px', color: 'var(--text-primary)' }}>{title}</h2>
          {subtitle && <span className="text-muted" style={{ fontSize: '15px', color: 'var(--text-muted)' }}>{subtitle}</span>}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
        {actions && (
          <div style={{ display: 'flex', gap: '12px', marginRight: '16px' }}>
            {actions}
          </div>
        )}
        
        {/* User Profile matching PPTX */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <span style={{ color: 'var(--color-brand-red)', fontSize: '12px', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>OPERATOR_01</span>
            <span style={{ color: 'var(--text-dimmed)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>ADMIN | GLOBAL SCOPE</span>
          </div>
          <div style={{ 
            width: '40px', height: '40px', 
            borderRadius: '50%', 
            backgroundColor: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--text-secondary)',
            fontSize: '14px',
            fontFamily: 'var(--font-heading)',
            fontWeight: 600
          }}>
            OP
          </div>
        </div>
      </div>
    </div>
  );
};

export default TopBar;
