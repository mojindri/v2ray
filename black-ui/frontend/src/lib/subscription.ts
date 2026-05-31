import type { Settings } from "./types";

const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

export function subscriptionUrl(settings: Settings | null, token: string): string {
  if (!settings || !token) return "";
  return `${subscriptionBaseUrl(settings)}/sub/${token}`;
}

function subscriptionBaseUrl(settings: Settings): string {
  const configured = settings.publicBaseUrl.trim();
  if (!configured) return currentOrigin();

  try {
    const url = new URL(configured);
    const current = currentOrigin();
    if (current) {
      const currentUrl = new URL(current);
      if (LOCAL_HOSTS.has(url.hostname) && !LOCAL_HOSTS.has(currentUrl.hostname)) {
        return currentUrl.origin;
      }
    }
    return trimTrailingSlash(url.toString());
  } catch {
    return trimTrailingSlash(configured);
  }
}

function currentOrigin(): string {
  if (typeof window === "undefined") return "";
  return window.location.origin;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
