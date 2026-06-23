import React from 'react';
import Card from './Card';

const AUTH_TYPES = [
  { value: 'form',    label: 'Form Login' },
  { value: 'bearer',  label: 'Bearer Token / API Key' },
  { value: 'cookie',  label: 'Session Capture / Cookie Jar' },
];

function Field({ label, htmlFor, children }) {
  return (
    <div>
      <label
        htmlFor={htmlFor}
        style={{
          display: 'block', marginBottom: '6px', fontSize: '11px',
          fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
          textTransform: 'uppercase', letterSpacing: '0.5px',
        }}
      >
        {label}
      </label>
      {children}
    </div>
  );
}

function SecretInput({ value, onChange, show, onToggle, placeholder, id, label }) {
  return (
    <Field label={label} htmlFor={id}>
      <div style={{ position: 'relative' }}>
        <input
          id={id}
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="off"
          spellCheck={false}
          style={{ width: '100%', paddingRight: '36px', boxSizing: 'border-box' }}
        />
        <button
          type="button"
          onClick={onToggle}
          aria-label={show ? 'Hide' : 'Show'}
          style={{
            position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)',
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: '0', lineHeight: 1, fontSize: '15px',
          }}
        >
          {show ? '🙈' : '👁'}
        </button>
      </div>
    </Field>
  );
}

export default function CredentialsCard({
  mode,
  authType,        setAuthType,
  username,        setUsername,
  password,        setPassword,        showPassword,  setShowPassword,
  token,           setToken,           showToken,     setShowToken,
  headerName,      setHeaderName,
  cookieJar,       setCookieJar,
  loginUrl,        setLoginUrl,
  onTestCredentials,
  testingCreds,
  testResult,
}) {
  if (mode === 'blackbox') return null;

  return (
    <Card title="Credentials">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

        {/* Auth Type */}
        <Field label="Authentication Type" htmlFor="cred-auth-type">
          <select
            id="cred-auth-type"
            value={authType}
            onChange={e => setAuthType(e.target.value)}
            style={{ width: '100%' }}
          >
            {AUTH_TYPES.map(t => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </Field>

        {/* Form Login */}
        {authType === 'form' && (
          <>
            <Field label="Username" htmlFor="cred-username">
              <input
                id="cred-username"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="admin"
                autoComplete="off"
                spellCheck={false}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </Field>
            <SecretInput
              id="cred-password"
              label="Password"
              value={password}
              onChange={setPassword}
              show={showPassword}
              onToggle={() => setShowPassword(v => !v)}
              placeholder="••••••••"
            />
            <Field label="Login URL" htmlFor="cred-login-url">
              <input
                id="cred-login-url"
                type="text"
                value={loginUrl}
                onChange={e => setLoginUrl(e.target.value)}
                placeholder="https://target.com/login"
                autoComplete="off"
                spellCheck={false}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </Field>
          </>
        )}

        {/* Bearer Token */}
        {authType === 'bearer' && (
          <>
            <SecretInput
              id="cred-token"
              label="Token / API Key"
              value={token}
              onChange={setToken}
              show={showToken}
              onToggle={() => setShowToken(v => !v)}
              placeholder="eyJhbGciOiJIUzI1NiJ9…"
            />
            <Field label="Header Name" htmlFor="cred-header-name">
              <input
                id="cred-header-name"
                type="text"
                value={headerName}
                onChange={e => setHeaderName(e.target.value)}
                placeholder="Authorization"
                autoComplete="off"
                spellCheck={false}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </Field>
            <Field label="Validation URL (optional)" htmlFor="cred-bearer-validation-url">
              <input
                id="cred-bearer-validation-url"
                type="text"
                value={loginUrl}
                onChange={e => setLoginUrl(e.target.value)}
                placeholder="https://target.com/api/me"
                autoComplete="off"
                spellCheck={false}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </Field>
          </>
        )}

        {/* Cookie Jar */}
        {authType === 'cookie' && (
          <>
            <Field label="Cookie Header (paste raw Cookie: value)" htmlFor="cred-cookie-jar">
              <textarea
                id="cred-cookie-jar"
                value={cookieJar}
                onChange={e => setCookieJar(e.target.value)}
                placeholder={'session=abc123; role=admin; csrf_token=xyz'}
                autoComplete="off"
                spellCheck={false}
                rows={4}
                style={{
                  width: '100%', boxSizing: 'border-box',
                  fontFamily: 'var(--font-mono)', fontSize: '11px',
                  resize: 'vertical',
                }}
              />
            </Field>
            <div style={{ fontSize: '10px', color: 'var(--text-dimmed)', fontFamily: 'var(--font-mono)' }}>
              Tip: Copy from DevTools → Network → Request Headers → Cookie, or export via Burp Suite.
              The "Cookie:" prefix is stripped automatically.
            </div>
            <Field label="Validation URL (optional)" htmlFor="cred-cookie-validation-url">
              <input
                id="cred-cookie-validation-url"
                type="text"
                value={loginUrl}
                onChange={e => setLoginUrl(e.target.value)}
                placeholder="https://target.com/dashboard"
                autoComplete="off"
                spellCheck={false}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </Field>
          </>
        )}

        {/* Test Credentials Button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', paddingTop: '4px', borderTop: '1px solid var(--border-color)' }}>
          <button
            type="button"
            onClick={onTestCredentials}
            disabled={testingCreds}
            style={{
              padding: '6px 14px', borderRadius: '4px', fontSize: '11px',
              fontFamily: 'var(--font-heading)', letterSpacing: '0.8px',
              textTransform: 'uppercase', cursor: testingCreds ? 'not-allowed' : 'pointer',
              border: '1px solid var(--border-secondary)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              display: 'flex', alignItems: 'center', gap: '6px',
              opacity: testingCreds ? 0.6 : 1,
            }}
          >
            {testingCreds ? (
              <>
                <svg viewBox="0 0 24 24" style={{ width: 12, height: 12, animation: 'spin 1s linear infinite' }}>
                  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="32" strokeLinecap="round" />
                </svg>
                Testing…
              </>
            ) : (
              'Test Credentials'
            )}
          </button>

          {testResult && (
            <span style={{
              fontSize: '12px', fontFamily: 'var(--font-mono)',
              color: testResult.ok ? 'var(--color-success)' : 'var(--color-critical)',
            }}>
              {testResult.ok ? '✓' : '✗'} {testResult.message}
            </span>
          )}
        </div>

      </div>
    </Card>
  );
}
