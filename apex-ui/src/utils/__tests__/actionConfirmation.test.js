import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  applyActionConfirmations,
  prepareActionConfirmations,
} from '../actionConfirmation';

const confirmation = (engine = 'webforge', action = 'scan') => ({
  schema_version: 'forge-action-confirmation-v1',
  confirmed: true,
  job_id: 'job-fixture',
  target: `sha256:${'a'.repeat(64)}`,
  engine,
  action,
  issued_at: '2026-07-31T12:00:00Z',
  binding_digest: 'b'.repeat(64),
});

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe('dashboard action confirmation contract', () => {
  it('prepares scope-bound confirmations before launch without sending credentials', async () => {
    const responsePayload = {
      job_id: 'job-fixture',
      scope: ['127.0.0.1/32'],
      exclude: [],
      confirmations: [confirmation()],
      authorized: false,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue(responsePayload),
    });
    vi.stubGlobal('fetch', fetchMock);

    const intent = {
      intent: 'scan.start',
      target: 'https://127.0.0.1/',
      scope: ['127.0.0.1/32'],
      exclude: [],
      scan_type: 'web',
    };
    const result = await prepareActionConfirmations(intent);

    expect(result).toEqual(responsePayload);
    const [, options] = fetchMock.mock.calls[0];
    expect(JSON.parse(options.body)).toEqual(intent);
    expect(options.body).not.toContain('password');
    expect(options.body).not.toContain('token');
  });

  it('binds single and multi-action bundles to the final launch payload', () => {
    const base = { target: 'https://127.0.0.1/', auth_profile: { username: 'operator' } };
    const single = applyActionConfirmations(base, {
      job_id: 'job-single',
      scope: ['127.0.0.1/32'],
      exclude: [],
      confirmations: [confirmation()],
    });
    expect(single).toMatchObject({
      job_id: 'job-single',
      scope: ['127.0.0.1/32'],
      confirmation: confirmation(),
    });
    expect(single.confirmations).toBeUndefined();

    const network = confirmation('netforge', 'web_to_network');
    const multi = applyActionConfirmations(base, {
      job_id: 'job-vapt',
      scope: ['127.0.0.1/32', '127.0.0.2/32'],
      exclude: [],
      network_target: '127.0.0.2',
      web_scope: ['127.0.0.1/32'],
      network_scope: ['127.0.0.2/32'],
      confirmations: [confirmation(), network],
    });
    expect(multi.confirmation).toBeUndefined();
    expect(multi.confirmations).toEqual([confirmation(), network]);
    expect(multi.network_target).toBe('127.0.0.2');
    expect(multi.web_scope).toEqual(['127.0.0.1/32']);
    expect(multi.network_scope).toEqual(['127.0.0.2/32']);
  });

  it('rejects a response that presents confirmation preparation as authorization', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        job_id: 'job-fixture',
        scope: ['127.0.0.1/32'],
        exclude: [],
        confirmations: [confirmation()],
        authorized: true,
      }),
    }));

    await expect(prepareActionConfirmations({ intent: 'scan.start' }))
      .rejects.toThrow('invalid confirmation contract');
  });
});
