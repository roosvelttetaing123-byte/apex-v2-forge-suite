import React from 'react';

const colors = {
  critical: { bg: 'rgba(255,68,68,0.12)', border: 'rgba(255,68,68,0.25)', text: '#ff4444' },
  high: { bg: 'rgba(255,140,0,0.12)', border: 'rgba(255,140,0,0.25)', text: '#ff8c00' },
  medium: { bg: 'rgba(255,196,0,0.12)', border: 'rgba(255,196,0,0.25)', text: '#ffc400' },
  low: { bg: 'rgba(0,216,240,0.12)', border: 'rgba(0,216,240,0.25)', text: '#00d8f0' },
  active: { bg: 'rgba(0,200,83,0.12)', border: 'rgba(0,200,83,0.25)', text: '#00c853' },
  paused: { bg: 'rgba(255,196,0,0.12)', border: 'rgba(255,196,0,0.25)', text: '#ffc400' },
  info: { bg: 'rgba(41,121,255,0.12)', border: 'rgba(41,121,255,0.25)', text: '#2979ff' },
  default: { bg: 'rgba(122,141,176,0.12)', border: 'rgba(122,141,176,0.25)', text: '#7a8db0' }
};

const Badge = ({ children, severity = 'default', style }) => {
  const colorKey = severity.toLowerCase();
  const theme = colors[colorKey] || colors.default;

  return (
    <span style={{
      backgroundColor: theme.bg,
      border: `1px solid ${theme.border}`,
      color: theme.text,
      borderRadius: '3px',
      padding: '2px 8px',
      fontSize: '11px',
      fontFamily: 'var(--font-mono)',
      textTransform: 'uppercase',
      display: 'inline-flex',
      alignItems: 'center',
      ...style
    }}>
      {children}
    </span>
  );
};

export default Badge;
