import { Call, Events } from "@wailsio/runtime";

const PREFIX = "github.com/DestroyersTaken/SentinelProxy/internal/service.API.";

/** Calls a method of the Go service. Errors returned by Go reject the promise. */
export async function call<T = unknown>(method: string, ...args: unknown[]): Promise<T> {
  try {
    return (await Call.ByName(PREFIX + method, ...args)) as T;
  } catch (e: any) {
    throw new Error(cleanError(e));
  }
}

function cleanError(e: any): string {
  let msg = e?.message ?? String(e);
  try {
    const parsed = JSON.parse(msg);
    msg = parsed.message ?? msg;
  } catch {}
  return String(msg).replace(/^.*?API\.\w+: /, "");
}

/** Subscribes to a backend event; returns an unsubscribe function. */
export function on<T = unknown>(name: string, cb: (data: T) => void): () => void {
  return Events.On(name, (ev: any) => cb(ev?.data as T));
}
