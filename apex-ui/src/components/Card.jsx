import React from 'react';

const Card = ({ children, className = '', title, headerRight, noPadding = false, style, onClick }) => {
  return (
    <div 
      className={`card ${className}`} 
      onClick={onClick}
      style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        borderRadius: '4px',
        display: 'flex',
        flexDirection: 'column',
        cursor: onClick ? 'pointer' : undefined,
        ...style
      }}
    >
      {(title || headerRight) && (
        <div style={{
          padding: '12px 16px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          {title && <h3 style={{ fontSize: '14px', color: 'var(--text-primary)', margin: 0, fontWeight: 500 }}>{title}</h3>}
          {headerRight && <div>{headerRight}</div>}
        </div>
      )}
      <div style={{ padding: noPadding ? 0 : '16px', flex: 1, display: 'flex', flexDirection: 'column' }}>
        {children}
      </div>
    </div>
  );
};

export default Card;
