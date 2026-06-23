import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import CredentialsCard from '../CredentialsCard';

// Minimal prop set for a controlled component
function makeProps(overrides = {}) {
  return {
    mode: 'greybox',
    authType: 'form',        setAuthType: vi.fn(),
    username: '',            setUsername: vi.fn(),
    password: '',            setPassword: vi.fn(),
    showPassword: false,     setShowPassword: vi.fn(),
    token: '',               setToken: vi.fn(),
    showToken: false,        setShowToken: vi.fn(),
    headerName: 'Authorization', setHeaderName: vi.fn(),
    cookieJar: '',           setCookieJar: vi.fn(),
    loginUrl: '',            setLoginUrl: vi.fn(),
    onTestCredentials: vi.fn(),
    testingCreds: false,
    testResult: null,
    ...overrides,
  };
}

describe('CredentialsCard', () => {
  // ── Visibility ────────────────────────────────────────────────────────

  it('renders nothing when mode is blackbox', () => {
    const { container } = render(<CredentialsCard {...makeProps({ mode: 'blackbox' })} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders the card when mode is greybox', () => {
    render(<CredentialsCard {...makeProps({ mode: 'greybox' })} />);
    expect(screen.getByText('Credentials')).toBeInTheDocument();
  });

  it('renders the card when mode is whitebox', () => {
    render(<CredentialsCard {...makeProps({ mode: 'whitebox' })} />);
    expect(screen.getByText('Credentials')).toBeInTheDocument();
  });

  // ── Auth type: form ───────────────────────────────────────────────────

  it('shows username, password, and login URL fields for form auth', () => {
    render(<CredentialsCard {...makeProps({ authType: 'form' })} />);
    expect(screen.getByPlaceholderText('admin')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('••••••••')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('https://target.com/login')).toBeInTheDocument();
  });

  it('does NOT show cookie textarea for form auth', () => {
    render(<CredentialsCard {...makeProps({ authType: 'form' })} />);
    expect(screen.queryByRole('textbox', { name: /cookie/i })).toBeNull();
  });

  // ── Auth type: bearer ─────────────────────────────────────────────────

  it('shows token and header name fields for bearer auth', () => {
    render(<CredentialsCard {...makeProps({ authType: 'bearer' })} />);
    expect(screen.getByPlaceholderText(/eyJhbGciOi/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Authorization')).toBeInTheDocument();
  });

  it('does NOT show username/password fields for bearer auth', () => {
    render(<CredentialsCard {...makeProps({ authType: 'bearer' })} />);
    expect(screen.queryByPlaceholderText('admin')).toBeNull();
    expect(screen.queryByPlaceholderText('••••••••')).toBeNull();
  });

  // ── Auth type: cookie ─────────────────────────────────────────────────

  it('shows cookie textarea for cookie auth type', () => {
    render(<CredentialsCard {...makeProps({ authType: 'cookie' })} />);
    expect(screen.getByRole('textbox', { name: /cookie header/i })).toBeInTheDocument();
  });

  it('does NOT show username or password for cookie auth type', () => {
    render(<CredentialsCard {...makeProps({ authType: 'cookie' })} />);
    expect(screen.queryByPlaceholderText('admin')).toBeNull();
    expect(screen.queryByPlaceholderText('••••••••')).toBeNull();
  });

  // ── Security: autocomplete=off ────────────────────────────────────────

  it('password field has autocomplete=off', () => {
    render(<CredentialsCard {...makeProps({ authType: 'form' })} />);
    const pwd = screen.getByPlaceholderText('••••••••');
    expect(pwd).toHaveAttribute('autocomplete', 'off');
  });

  it('username field has autocomplete=off', () => {
    render(<CredentialsCard {...makeProps({ authType: 'form' })} />);
    const user = screen.getByPlaceholderText('admin');
    expect(user).toHaveAttribute('autocomplete', 'off');
  });

  it('cookie textarea has autocomplete=off', () => {
    render(<CredentialsCard {...makeProps({ authType: 'cookie' })} />);
    const textarea = screen.getByRole('textbox', { name: /cookie header/i });
    expect(textarea).toHaveAttribute('autocomplete', 'off');
  });

  // ── Security: password field type ────────────────────────────────────

  it('password input defaults to type=password', () => {
    render(<CredentialsCard {...makeProps({ authType: 'form' })} />);
    const pwd = screen.getByPlaceholderText('••••••••');
    expect(pwd).toHaveAttribute('type', 'password');
  });

  it('password becomes type=text when showPassword=true', () => {
    render(<CredentialsCard {...makeProps({ authType: 'form', showPassword: true })} />);
    const pwd = screen.getByPlaceholderText('••••••••');
    expect(pwd).toHaveAttribute('type', 'text');
  });

  // ── Show/hide toggle ──────────────────────────────────────────────────

  it('clicking the eye toggle calls setShowPassword', () => {
    const setShowPassword = vi.fn();
    render(<CredentialsCard {...makeProps({ authType: 'form', setShowPassword })} />);
    const toggle = screen.getByLabelText('Show');
    fireEvent.click(toggle);
    expect(setShowPassword).toHaveBeenCalledOnce();
  });

  // ── Test Credentials button ───────────────────────────────────────────

  it('calls onTestCredentials when the button is clicked', () => {
    const onTestCredentials = vi.fn();
    render(<CredentialsCard {...makeProps({ onTestCredentials })} />);
    fireEvent.click(screen.getByText('Test Credentials'));
    expect(onTestCredentials).toHaveBeenCalledOnce();
  });

  it('disables the Test Credentials button while testingCreds=true', () => {
    render(<CredentialsCard {...makeProps({ testingCreds: true })} />);
    expect(screen.getByText('Testing…').closest('button')).toBeDisabled();
  });

  it('shows success testResult in green', () => {
    render(<CredentialsCard {...makeProps({ testResult: { ok: true, message: 'Auth verified' } })} />);
    const msg = screen.getByText(/Auth verified/);
    expect(msg).toBeInTheDocument();
    expect(msg).toHaveStyle({ color: 'var(--color-success)' });
  });

  it('shows failure testResult in red', () => {
    render(<CredentialsCard {...makeProps({ testResult: { ok: false, message: 'Auth failed' } })} />);
    const msg = screen.getByText(/Auth failed/);
    expect(msg).toBeInTheDocument();
    expect(msg).toHaveStyle({ color: 'var(--color-critical)' });
  });
});
