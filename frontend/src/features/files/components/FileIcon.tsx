import { FileArchive, FileQuestion, FileText, Folder, Link2 } from "lucide-react";
import type { SftpEntry } from "../../../types";

export function FileIcon({ entry, size = 16 }: { entry: SftpEntry; size?: number }) {
  if (entry.kind === "dir") return <Folder size={size} className="fs-kind-dir" aria-hidden />;
  if (entry.kind === "symlink") return <Link2 size={size} className="fs-kind-link" aria-hidden />;
  if (entry.kind === "other") return <FileQuestion size={size} className="fs-kind-other" aria-hidden />;
  const lower = entry.display.toLowerCase();
  if (lower.endsWith(".zip") || lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return <FileArchive size={size} className="fs-kind-archive" aria-hidden />;
  }
  return <FileText size={size} className="fs-kind-file" aria-hidden />;
}
