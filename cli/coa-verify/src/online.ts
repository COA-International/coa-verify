// Optional online mode. Only ever talks to the base URL the user configured explicitly; nothing inside a
// record, bundle or server response is fetched. Redirects are refused, size and time are bounded.
export interface OnlineFetchOptions {
  baseUrl: string;
  timeoutMs?: number;
  maxBytes?: number;
  fetchImpl?: typeof fetch;
}

export class OnlineError extends Error {
  constructor(
    public reason: "bad_base_url" | "network" | "redirect_refused" | "http_status" | "too_large" | "bad_content" | "timeout",
    message: string,
    public status?: number,
  ) {
    super(message);
    this.name = "OnlineError";
  }
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Normalise the configured base URL: https only (plain http only for loopback development hosts). */
export function normalizeBaseUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new OnlineError("bad_base_url", `not a valid URL: ${raw}`);
  }
  const loopback = LOCAL_HOSTS.has(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new OnlineError("bad_base_url", "the online URL must be https:// (http:// is allowed only for localhost)");
  }
  if (u.username || u.password) throw new OnlineError("bad_base_url", "credentials in the URL are not allowed");
  if (u.search || u.hash) throw new OnlineError("bad_base_url", "the online URL must not contain a query or fragment");
  return (u.origin + u.pathname).replace(/\/+$/, "");
}

export async function getJson(path: string, opts: OnlineFetchOptions): Promise<unknown> {
  const base = normalizeBaseUrl(opts.baseUrl);
  const url = base + path;
  const doFetch = opts.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    let response: Response;
    try {
      response = await doFetch(url, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { accept: "application/json", "user-agent": "coa-verify" },
      });
    } catch (e) {
      if (controller.signal.aborted) throw new OnlineError("timeout", "the request timed out");
      throw new OnlineError("network", `request failed: ${(e as Error).message}`);
    }
    if (response.status >= 300 && response.status < 400) {
      throw new OnlineError("redirect_refused", `the server answered with a redirect (${response.status}); redirects are not followed`);
    }
    if (response.status !== 200) throw new OnlineError("http_status", `the server answered HTTP ${response.status}`, response.status);
    const type = response.headers.get("content-type") ?? "";
    if (!/^application\/(json|problem\+json)/i.test(type)) throw new OnlineError("bad_content", "the response is not JSON");
    const max = opts.maxBytes ?? 1024 * 1024;
    const chunks: Uint8Array[] = [];
    let total = 0;
    const reader = response.body?.getReader();
    if (!reader) throw new OnlineError("bad_content", "empty response body");
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max) {
        await reader.cancel();
        throw new OnlineError("too_large", "the response exceeded the size limit");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      bytes.set(c, off);
      off += c.length;
    }
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new OnlineError("bad_content", "the response is not valid JSON");
    }
  } finally {
    clearTimeout(timer);
  }
}

export interface OnlineStatus {
  base_url: string;
  as_of: string | null;
  standing: string | null;
  standing_events: Array<{ kind: string; effective_at: string; public_reason: string | null }>;
  source_warning: string | null;
  replacement_verification_code: string | null;
  membership: { status: string | null; fresh: boolean | null; last_checked_at: string | null; source: string | null; note: string | null } | null;
  key_status: string | null;
  trust_warning: string | null;
  anchor_status: string | null;
  anchor_public: boolean | null;
  record_matches_local: boolean;
  mismatch_reasons: string[];
  proof: unknown | null;
}

type Bag = Record<string, unknown>;
const bag = (v: unknown): Bag => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Bag) : {});
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/**
 * Fetch current public status for a record whose signature already verified locally.
 * `code` and `issuanceId` come from the verified payload, never from anything the server said.
 */
export async function fetchOnlineStatus(
  code: string,
  issuanceId: string,
  opts: OnlineFetchOptions,
  wantAnchorProof: boolean,
): Promise<OnlineStatus> {
  const base = normalizeBaseUrl(opts.baseUrl);
  const body = bag(await getJson(`/api/v1/public/verifications/${encodeURIComponent(code)}`, opts));
  const record = bag(body.record);
  const standing = bag(body.standing);
  const membership = body.membership === undefined ? null : bag(body.membership);
  const integrity = bag(body.integrity);
  const anchor = bag(body.anchor);
  const freshness = bag(body.freshness);

  const reasons: string[] = [];
  if (record.verification_code !== code) reasons.push("server returned a different verification_code");
  if (record.issuance_id !== issuanceId) reasons.push("server returned a different issuance_id");

  let proof: unknown | null = null;
  if (wantAnchorProof && (anchor.anchor_status === "pending" || anchor.anchor_status === "confirmed")) {
    try {
      proof = await getJson(`/api/v1/public/verifications/${encodeURIComponent(code)}/anchor-proof`, opts);
    } catch (e) {
      if (!(e instanceof OnlineError && e.reason === "http_status")) throw e;
    }
  }

  const events = Array.isArray(standing.events) ? standing.events : [];
  return {
    base_url: base,
    as_of: str(freshness.as_of),
    standing: str(standing.standing),
    standing_events: events.map((e) => {
      const b = bag(e);
      return { kind: str(b.kind) ?? "?", effective_at: str(b.effective_at) ?? "?", public_reason: str(b.public_reason) };
    }),
    source_warning: str(standing.source_warning),
    replacement_verification_code: str(standing.replacement_verification_code),
    membership: membership && {
      status: str(membership.status),
      fresh: typeof membership.fresh === "boolean" ? membership.fresh : null,
      last_checked_at: str(membership.last_checked_at),
      source: str(membership.source),
      note: str(membership.note),
    },
    key_status: str(integrity.key_status),
    trust_warning: str(integrity.trust_warning),
    anchor_status: str(anchor.anchor_status),
    anchor_public: typeof anchor.public === "boolean" ? anchor.public : null,
    record_matches_local: reasons.length === 0,
    mismatch_reasons: reasons,
    proof,
  };
}
