import { api } from "./bridge";
import type { Server, ServerDraft, SessionStatus } from "./types";
export function groupMembers(servers: readonly Server[], group: string) { return servers.filter(server => server.group === group); }
export function fleetRollup(servers: readonly Server[], statuses: ReadonlyMap<string, SessionStatus>) {
  return { total: servers.length, connected: servers.filter(server => statuses.get(server.id) === "ready").length, errors: servers.filter(server => statuses.get(server.id) === "error").length };
}
export function serverGroupDraft(server: Server, group: string): ServerDraft {
  const { id, name, host, port, user, auth_method, key_path, key_has_passphrase, tags, via_server_id, history_shell } = server;
  return { id, name, host, port, user, auth_method, key_path, key_has_passphrase, tags, via_server_id, history_shell, group };
}
export function validateGroupName(group: string): string | null {
  if (/[\x00-\x1f\x7f]/.test(group)) return "Group names cannot contain control characters.";
  if (!group.trim()) return null;
  const segments = group.trim().split("/");
  if (segments.length > 2) return "Use a group or parent/child group path.";
  if (segments.some(segment => !segment.trim())) return "Each group path segment needs a name.";
  return null;
}
export async function moveGroupProfiles(servers: readonly Server[], group: string) {
  const invalid = validateGroupName(group); if (invalid) throw new Error(invalid);
  const updated: Server[] = []; const failures: Array<{ id: string; name: string; message: string }> = [];
  // Independent per-profile saves match the native contract. Report partial results.
  for (const server of servers) {
    try { updated.push((await api.servers.save(serverGroupDraft(server, group.trim()))).server); }
    catch (error) { failures.push({ id: server.id, name: server.name, message: error instanceof Error ? error.message : String(error) }); }
  }
  return { updated, failures };
}
