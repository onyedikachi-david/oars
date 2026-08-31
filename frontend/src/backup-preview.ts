export const BACKUP_PREVIEW_MODES = [
  "populated",
  "empty",
  "refreshing",
  "disconnected",
  "rclone-missing",
  "cron-stopped",
  "partial-import",
  "editor-aws-key",
  "editor-aws-iam",
  "editor-r2",
  "editor-minio-http-warning",
  "test-plan",
  "test-running",
  "test-cleanup-failed",
  "schedule-secret-disclosure",
  "schedule-conflict",
  "run-copy",
  "run-sync-confirm",
  "run-no-changes",
  "run-failed",
  "run-cancel-requested",
  "run-interrupted",
  "delete-partial-cleanup",
  "install-plan",
  "unsupported-target",
] as const;

export type BackupPreviewMode = typeof BACKUP_PREVIEW_MODES[number];

const BACKUP_PREVIEW_MODE_SET = new Set<string>(BACKUP_PREVIEW_MODES);

export function readBackupPreviewMode(): BackupPreviewMode | null {
  if (typeof window === "undefined" || document.documentElement.dataset.previewVariant === undefined) return null;
  const requested = new URLSearchParams(window.location.search).get("backups");
  return requested !== null && BACKUP_PREVIEW_MODE_SET.has(requested)
    ? requested as BackupPreviewMode
    : null;
}
