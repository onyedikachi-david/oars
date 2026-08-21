import type { LocalEntry, RemotePath, SftpEntry } from "../../types";

export interface FilesTabProps {
  serverId: string;
  onNavigateToDeploy?: () => void;
}

export interface EditorState {
  path: RemotePath;
  pathKey: string;
  display: string;
  entry: SftpEntry;
  content: string;
  sha256: string;
  dirty: boolean;
  phase: "loading" | "editing" | "saving" | "error";
  error: string | null;
  conflict: string | null;
  tooLarge: boolean;
}

export interface UploadIntent {
  file: File;
  relativePath?: string;
}

export interface LocalPaneState {
  path: string | null;
  entries: LocalEntry[];
  loading: boolean;
  error: string | null;
  truncated: boolean;
  selected: string[];
}

export type DialogState =
  | { kind: "mkdir" }
  | { kind: "rename"; entry: SftpEntry }
  | { kind: "chmod"; entry: SftpEntry }
  | { kind: "delete"; entries: SftpEntry[] }
  | { kind: "unzip"; entry: SftpEntry }
  | { kind: "upload"; intents: UploadIntent[] }
  | { kind: "uploadLocal"; entries: LocalEntry[] }
  | null;
