import { apiFetch } from '../config/api';

export const dashboardErrorMessage = (payload, fallback) => {
  const detail = payload?.detail;
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (detail && typeof detail === 'object') {
    return detail.reason || detail.reason_code || fallback;
  }
  return payload?.reason || payload?.reason_code || fallback;
};

/**
 * Ask the dashboard to mint the existing exact-action confirmation records.
 * This endpoint validates scope but creates no job, worker, or authorization.
 */
export const prepareActionConfirmations = async (intent) => {
  const response = await apiFetch('/api/v1/action-confirmations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(intent),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(dashboardErrorMessage(payload, `Confirmation preparation failed (${response.status})`));
  }
  if (
    typeof payload.job_id !== 'string'
    || !Array.isArray(payload.scope)
    || !Array.isArray(payload.exclude)
    || !Array.isArray(payload.confirmations)
    || payload.confirmations.length === 0
    || payload.authorized !== false
    || (
      payload.network_target
      && (!Array.isArray(payload.web_scope) || !Array.isArray(payload.network_scope))
    )
  ) {
    throw new Error('Dashboard returned an invalid confirmation contract');
  }
  return payload;
};

/** Bind a prepared confirmation bundle to the unchanged launch payload. */
export const applyActionConfirmations = (launchPayload, bundle) => {
  const payload = {
    ...launchPayload,
    job_id: bundle.job_id,
    scope: [...bundle.scope],
    exclude: [...bundle.exclude],
  };
  if (bundle.network_target) payload.network_target = bundle.network_target;
  if (Array.isArray(bundle.web_scope)) payload.web_scope = [...bundle.web_scope];
  if (Array.isArray(bundle.network_scope)) payload.network_scope = [...bundle.network_scope];
  if (bundle.confirmations.length === 1) {
    payload.confirmation = bundle.confirmations[0];
    delete payload.confirmations;
  } else {
    payload.confirmations = [...bundle.confirmations];
    delete payload.confirmation;
  }
  return payload;
};
