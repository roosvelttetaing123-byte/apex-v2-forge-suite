import React from 'react';

const Button = ({
  children,
  variant = 'primary',
  onClick = undefined,
  className = '',
  style = {},
  fullWidth = false,
  disabled = false,
  title = undefined,
}) => {
  const baseStyle = {
    padding: '8px 16px',
    borderRadius: '4px',
    cursor: disabled ? 'not-allowed' : 'pointer',
    border: 'none',
    opacity: disabled ? 0.4 : 1,
    fontFamily: 'var(--font-heading)',
    fontSize: '14px',
    letterSpacing: '1.5px',
    fontWeight: 600,
    textTransform: 'uppercase',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    transition: 'all 0.2s',
    width: fullWidth ? '100%' : 'auto',
    ...style
  };

  const variants = {
    primary: {
      backgroundColor: 'var(--color-brand-red)',
      color: '#fff',
    },
    secondary: {
      backgroundColor: 'transparent',
      border: '1px solid var(--border-color)',
      color: 'var(--text-secondary)',
    }
  };

  const hoverStyles = `
    .btn-custom:hover.btn-primary { background-color: var(--color-brand-red-hover); }
    .btn-custom:hover.btn-secondary { border-color: var(--text-very-dim); color: var(--text-primary); }
  `;

  return (
    <>
      <style>{hoverStyles}</style>
      <button 
        className={`btn-custom btn-${variant} ${className}`}
        style={{ ...baseStyle, ...variants[variant] }}
        onClick={disabled ? undefined : onClick}
        disabled={disabled}
        title={title}
      >
        {children}
      </button>
    </>
  );
};

export default Button;
