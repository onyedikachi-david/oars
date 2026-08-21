import type { AccessCoverage, AccessGrant, AccessScope, AccessServerView } from "./types";

export interface OnboardTargetChoice {
  serverId: string;
  serverName: string;
  enabled: boolean;
  kind: "account" | "read_only_role";
  name: string;
  accounts: string[];
}

export function grantKey(grant: AccessGrant): string {
  return `${grant.server_id}:${grant.user}:${grant.source_path}:${grant.line_hash}`;
}

export function phaseLabel(phase: string): string {
  const labels: Record<string, string> = {
    queued: "Queued",
    identity: "Reading account",
    sudo_probe: "Checking policy",
    enumerate: "Finding accounts",
    read_accounts: "Reading key sources",
    sshd_config: "Checking SSH policy",
    done: "Done",
    error: "Sync error",
  };
  return labels[phase] ?? phase;
}

export function defaultRoleAccountName(personName: string): string {
  const stem = personName
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "access";
  return `${stem}-readonly`;
}

export function isValidLinuxAccountName(name: string): boolean {
  return /^[a-z0-9_][a-z0-9_-]{0,63}$/.test(name);
}

export function parseFingerprintsInput(text: string): string[] {
  if (!text) return [];
  return text
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean);
}

export function validateIdentityInput(
  name: string,
  fingerprints: string[],
): { ok: boolean; error: string | null } {
  if (!name.trim() || fingerprints.length === 0) {
    return { ok: false, error: "Enter a name and at least one SHA-256 fingerprint." };
  }
  return { ok: true, error: null };
}

export function validateOnboardTargets(
  targets: OnboardTargetChoice[],
): { ok: boolean; error: string | null } {
  const enabled = targets.filter((target) => target.enabled);
  if (enabled.length === 0) {
    return { ok: false, error: "Select at least one server target." };
  }
  if (enabled.some((target) => !isValidLinuxAccountName(target.name))) {
    return { ok: false, error: "Each target needs a valid Linux account name." };
  }
  return { ok: true, error: null };
}

export function buildOnboardTargets(
  servers: AccessServerView[],
  selectedGrants: AccessGrant[],
): OnboardTargetChoice[] {
  return servers.map((server) => {
    const selectedGrant = selectedGrants.find((grant) => grant.server_id === server.server_id);
    const accounts = server.accounts.filter((account) => !account.skipped).map((account) => account.user);
    return {
      serverId: server.server_id,
      serverName: server.name,
      enabled: Boolean(selectedGrant),
      kind: "account",
      name: selectedGrant?.user ?? server.connected_user ?? accounts[0] ?? "",
      accounts,
    };
  });
}

export function computeAccessStatusText(
  scope: AccessScope | undefined,
  state: "scanning" | "canceled" | "done" | undefined,
  coverage: AccessCoverage | null,
): string {
  if (!scope && !state) return "No access snapshot";
  const scopeText = scope === "all_login_accounts" ? "Full-account scope" : "Connected-account scope";
  if (state === "scanning") return `Scanning · ${scopeText}`;
  if (state === "canceled") return `Scan canceled · ${scopeText}`;
  return `${scopeText} · ${coverage === "complete" ? "complete for this scope" : "partial coverage"}`;
}
