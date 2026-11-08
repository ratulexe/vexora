// Calls the Vexora API with a time limit, so a sleeping or stuck server produces a
// clear message instead of an endless "Investigating...".

export const ANALYSIS_TIMEOUT_MS = 90_000;
export const REGISTRATION_TIMEOUT_MS = 150_000; // A blockchain transaction can take up to a minute or two.
export const SLOW_NOTICE_MS = 15_000;

export async function postJson<T>(url: string, body: unknown, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    if (controller.signal.aborted) {
      throw new Error(
        `The server did not respond within ${Math.round(timeoutMs / 1000)} seconds. It may be waking up after a quiet period. Please try again in a minute.`,
      );
    }
    throw new Error(
      "Could not reach the Vexora server. Check your internet connection, or try again in a minute.",
      { cause: err },
    );
  } finally {
    clearTimeout(timer);
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail ?? `Request failed (${response.status})`);
  return data as T;
}
