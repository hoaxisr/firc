import { token } from "../data/auth.svelte";
import { t } from "../data/locale.svelte";

import { toast } from "./events";

const viteEnv = (import.meta as ImportMeta & { env?: { DEV?: boolean } }).env;
export const API_BASE = viteEnv?.DEV ? `http://${location.hostname}:6969/api/v1` : "/api/v1";

export class HttpError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export async function fetcher<T>(...args: any[]): Promise<T> {
  const url = args.shift();
  const options = args[0] || {};

  const quiet = options.quiet === true;
  delete options.quiet;

  if (token.current) {
    options.headers = {
      ...options.headers,
      Authorization: `Bearer ${token.current}`,
    };
  }

  if (args.length > 0) {
    args[0] = options;
  } else {
    args.push(options);
  }

  try {
    const res = await fetch(`${API_BASE}${url}`, ...args);

    if (res.status === 401) {
      token.reset();
      throw new Error("Unauthorized");
    }

    if (!res.ok || res.status < 200 || res.status > 299) {
      const error = new HttpError(res.body ? await res.text() : res.statusText, res.status);
      throw error;
    }
    return (await res.json()) as T;
  } catch (e) {
    console.error("Fetch error:", e);

    if (!quiet && (e as Error).message !== "Unauthorized") {
      let errorMessage = t("Request failed");
      try {
        const resBody = JSON.parse((e as Error).message);
        if (resBody?.error) {
          errorMessage = `${errorMessage}: ${resBody.error}`;
        }
      } catch {}
      toast.error(errorMessage);
    }
    throw e;
  }
}

fetcher.get = <T>(url: string, opts: { quiet?: boolean; signal?: AbortSignal } = {}) =>
  fetcher<T>(url, {
    method: "GET",
    ...opts,
  });

fetcher.post = <T>(url: string, body: any, opts: { quiet?: boolean } = {}) =>
  fetcher<T>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    ...opts,
  });

fetcher.put = <T>(url: string, body: any, opts: { quiet?: boolean } = {}) =>
  fetcher<T>(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    ...opts,
  });

fetcher.patch = <T>(url: string, body: any) =>
  fetcher<T>(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

fetcher.delete = <T>(url: string, opts: { quiet?: boolean } = {}) =>
  fetcher<T>(url, {
    method: "DELETE",
    ...opts,
  });
