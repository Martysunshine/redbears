/** Turn a backend `detail` into text fit for a person.
 *
 * Short machine codes (anon_daily_limit, chat_busy, …) are a contract with the
 * UI and pass through untouched so callers can branch on them. A {code, message}
 * envelope passes its message. Any OTHER string on a 5xx is replaced: that is
 * the one case where the text may be an exception's own words — hosts, ports,
 * paths — rather than something written for the user; the cause is in the
 * server log. 4xx strings are validation text meant for the user and stay.
 */
export const GENERIC_SERVER_ERROR = "Something went wrong on our side. Please try again.";

export const KNOWN_CODES = new Set([
  "anon_daily_limit",
  "chat_busy",
  "chat_one_at_a_time",
  "terms_acceptance_required",
  "job_not_found",
  "upload_daily_limit",
  "storage_limit",
  // nginx's own rate limiter (deploy/nginx/sites-available/oyster @ratelimited)
  "rate_limited",
]);

export function friendlyError(status: number, detail: unknown): string {
  if (typeof detail === "string") {
    if (KNOWN_CODES.has(detail) || status < 500) return detail;
    return GENERIC_SERVER_ERROR;
  }
  if (detail && typeof detail === "object") {
    const d = detail as { message?: unknown; code?: unknown };
    if (typeof d.message === "string") return d.message;
    if (typeof d.code === "string") return d.code;
  }
  return status >= 500 ? GENERIC_SERVER_ERROR : `Backend error ${status}`;
}
