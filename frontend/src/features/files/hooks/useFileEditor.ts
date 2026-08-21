import { useCallback, useEffect, useRef, useState } from "react";
import {
  EDITOR_MAX_BYTES,
  isConflictError,
  savedIdentityFallback,
} from "../../../editor-state";
import {
  rpDisplay,
  rpParent,
  rpSerialize,
  type RemotePath,
} from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { errMessage, fmtBytes } from "../formatters";
import type { EditorState } from "../types";
import { readRemoteFileChunks, writeRemoteFileAtomic } from "./editorIo";

export interface UseFileEditorParams {
  serverId: string;
  onRefreshAfterMutation: (path: RemotePath) => void;
}

export function useFileEditor({
  serverId,
  onRefreshAfterMutation,
}: UseFileEditorParams) {
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [dirtyCloseOpen, setDirtyCloseOpen] = useState(false);
  const editorRequestRef = useRef(0);

  // Server switch reset
  useEffect(() => {
    setEditor(null);
    editorRequestRef.current += 1;
    setDirtyCloseOpen(false);
  }, [serverId]);

  const openEditor = useCallback(
    async (entry: SftpEntry, path: RemotePath) => {
      const pathKey = rpSerialize(path);
      const display = rpDisplay(path);
      const requestId = ++editorRequestRef.current;

      const updateCurrentEditor = (update: (current: EditorState) => EditorState) => {
        setEditor((current) => {
          if (!current || current.pathKey !== pathKey || editorRequestRef.current !== requestId) return current;
          return update(current);
        });
      };

      if (entry.size > EDITOR_MAX_BYTES) {
        setEditor({
          path,
          pathKey,
          display,
          entry,
          content: "",
          sha256: "",
          dirty: false,
          phase: "error",
          error: `This file is ${fmtBytes(entry.size)} — the editor handles text files up to ${fmtBytes(EDITOR_MAX_BYTES)}.`,
          conflict: null,
          tooLarge: true,
        });
        return;
      }

      setEditor({
        path,
        pathKey,
        display,
        entry,
        content: "",
        sha256: "",
        dirty: false,
        phase: "loading",
        error: null,
        conflict: null,
        tooLarge: false,
      });

      try {
        const { text, sha256 } = await readRemoteFileChunks(serverId, path);
        if (editorRequestRef.current !== requestId) return;
        updateCurrentEditor((current) => ({
          ...current,
          content: text,
          sha256,
          dirty: false,
          phase: "editing",
          error: null,
        }));
      } catch (e) {
        if (editorRequestRef.current !== requestId) return;
        updateCurrentEditor((current) => ({
          ...current,
          phase: "error",
          error: errMessage(e),
        }));
      }
    },
    [serverId],
  );

  const updateEditorContent = useCallback((newContent: string) => {
    setEditor((current) => {
      if (!current) return current;
      return { ...current, content: newContent, dirty: true };
    });
  }, []);

  const saveEditor = useCallback(async () => {
    if (!editor || editor.phase !== "editing") return;
    const { path, content, sha256: currentSha, entry } = editor;
    setEditor((c) => (c ? { ...c, phase: "saving", error: null, conflict: null } : c));

    try {
      const bytes = new TextEncoder().encode(content);
      const identity = {
        size: entry.size,
        mtime: entry.mtime,
        sha256: currentSha,
      };
      const { sha256: newSha, updatedPath } = await writeRemoteFileAtomic(
        serverId,
        path,
        content,
        identity,
      );
      setEditor((c) => {
        if (!c) return c;
        const nextIdentity = savedIdentityFallback(bytes.length, newSha, Date.now() / 1000);
        const updatedEntry: SftpEntry = {
          ...entry,
          size: nextIdentity.size,
          mtime: nextIdentity.mtime,
        };
        return {
          ...c,
          path: updatedPath,
          pathKey: rpSerialize(updatedPath),
          display: rpDisplay(updatedPath),
          entry: updatedEntry,
          sha256: newSha,
          dirty: false,
          phase: "editing",
          error: null,
          conflict: null,
        };
      });
      onRefreshAfterMutation(rpParent(updatedPath));
    } catch (e) {
      const msg = errMessage(e);
      if (isConflictError(msg)) {
        setEditor((c) => (c ? { ...c, phase: "editing", conflict: msg } : c));
      } else {
        setEditor((c) => (c ? { ...c, phase: "editing", error: msg } : c));
      }
    }
  }, [editor, serverId, onRefreshAfterMutation]);

  const reloadEditor = useCallback(async () => {
    if (!editor) return;
    const { entry, path } = editor;
    await openEditor(entry, path);
  }, [editor, openEditor]);

  const closeEditor = useCallback(() => {
    if (!editor) return;
    if (editor.dirty) {
      setDirtyCloseOpen(true);
    } else {
      setEditor(null);
    }
  }, [editor]);

  const discardEditorAndClose = useCallback(() => {
    setDirtyCloseOpen(false);
    setEditor(null);
  }, []);

  const cancelDiscard = useCallback(() => setDirtyCloseOpen(false), []);

  return {
    editor,
    dirtyCloseOpen,
    openEditor,
    closeEditor,
    saveEditor,
    reloadEditor,
    updateEditorContent,
    discardEditorAndClose,
    cancelDiscard,
  };
}
