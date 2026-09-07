import type { DeployEnvVar, DeployPreflight, DeployPreflightStep } from "./types";

export const ENV_VALUE_LIMIT = 64 * 1024;
export const DEPLOY_OUTPUT_CAP = 200_000;

export function envVarNameOk(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

export interface ImportedEnvRow { name: string; value: string; secret: true; }
export interface BulkImportResult { rows: ImportedEnvRow[]; rejected: string[]; duplicates: string[]; preview: string; }

/** Parses dotenv-shaped lines without interpreting escapes or stripping
 * quotes. Every byte after the first `=` is preserved and every imported
 * value defaults to secret until the user explicitly changes the row. */
export function bulkImportEnv(input: string, existing: DeployEnvVar[]): BulkImportResult {
  const rows: ImportedEnvRow[] = [];
  const rejected: string[] = [];
  const duplicates: string[] = [];
  const seen = new Set(existing.map((item) => item.name));

  for (const original of input.split("\n")) {
    const line = original.endsWith("\r") ? original.slice(0, -1) : original;
    const leftTrimmed = line.trimStart();
    if (leftTrimmed.length === 0 || leftTrimmed.startsWith("#")) continue;
    const candidate = leftTrimmed.startsWith("export ") ? leftTrimmed.slice(7) : leftTrimmed;
    const eq = candidate.indexOf("=");
    if (eq < 0) { rejected.push(original); continue; }
    const name = candidate.slice(0, eq).trim();
    const value = candidate.slice(eq + 1);
    if (!envVarNameOk(name) || value.includes("\x00") || value.includes("\r") || value.length > ENV_VALUE_LIMIT) {
      rejected.push(original);
      continue;
    }
    if (seen.has(name)) { duplicates.push(name); continue; }
    seen.add(name);
    rows.push({ name, value, secret: true });
  }
  return {
    rows,
    rejected,
    duplicates,
    preview: rows.map((row) => `${row.name}=••••••••`).join("\n"),
  };
}

export function mergeImportedEnv(existing: DeployEnvVar[], rows: ImportedEnvRow[]): DeployEnvVar[] {
  return [...existing.map((row) => ({ ...row })), ...rows.map((row) => ({ name: row.name, secret: true, value: row.value, has_value: false }))];
}

export function approvalIds(preflight: DeployPreflight): string[] { return preflight.approvals.map((approval) => approval.id); }
export function preflightBlockers(preflight: DeployPreflight): string[] { return preflight.blockers.map((issue) => issue.message); }
export function preflightWarnings(preflight: DeployPreflight): string[] { return preflight.warnings.map((issue) => issue.message); }
export function needsApproval(preflight: DeployPreflight): boolean { return preflight.approvals.length > 0 || preflight.blockers.length > 0; }
export function describeMutation(step: DeployPreflightStep): string { return step.mutation || step.command; }

export type Cursors = Record<string, number>;
export function cursorsFromSteps(steps: Array<{ channel?: number; cursor?: number }>): Cursors {
  const out: Cursors = {};
  for (const step of steps) if (step.channel != null && step.cursor != null) out[String(step.channel)] = step.cursor;
  return out;
}

export function appendDeployOutput(acc: string, data: string | undefined, gap: number | undefined, alreadyGapped: boolean): { text: string; gapNoted: boolean } {
  const gapNoted = alreadyGapped || (gap != null && gap > 0);
  if (!data) return { text: acc, gapNoted };
  const next = acc + data;
  return { text: next.length > DEPLOY_OUTPUT_CAP ? next.slice(-DEPLOY_OUTPUT_CAP) : next, gapNoted };
}

export function formatHistoryTime(ms: number): string { return new Date(ms).toLocaleString(); }
