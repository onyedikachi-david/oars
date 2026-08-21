import { useState } from "react";
import { api, vault } from "../../../bridge";
import { bulkImportEnv, mergeImportedEnv, type BulkImportResult } from "../../../deploy-state";
import type { DeployApp, DeployAppInput } from "../../../types";
import type { EditorState } from "../types";
import { account, cloneApp, emptyEditor, messageOf } from "../utils";

export function useDeployEditor(
  serverId: string,
  onSaved: (appId: string) => Promise<void>,
  onError: (error: string | null) => void,
) {
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [editorOriginal, setEditorOriginal] = useState<DeployApp | null>(null);
  const [editorBusy, setEditorBusy] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [bulkPreview, setBulkPreview] = useState<BulkImportResult | null>(null);

  const openEditor = (app?: DeployApp) => {
    setEditor(app ? cloneApp(app) : emptyEditor(serverId));
    setEditorOriginal(app ?? null);
    setBulkText("");
    setBulkPreview(null);
    onError(null);
  };

  const closeEditor = () => {
    if (!editorBusy) {
      setEditor(null);
      setEditorOriginal(null);
      setBulkPreview(null);
      setBulkText("");
    }
  };

  const previewBulk = () => {
    if (!editor) return;
    setBulkPreview(bulkImportEnv(bulkText, editor.env_vars));
  };

  const applyBulkPreview = () => {
    if (!editor || !bulkPreview) return;
    setEditor({ ...editor, env_vars: mergeImportedEnv(editor.env_vars, bulkPreview.rows) });
    setBulkText("");
    setBulkPreview(null);
  };

  const saveEditor = async () => {
    if (!editor) return;
    if (!editor.name.trim() || !editor.folder.startsWith("/") || !editor.repo.url.trim()) {
      onError("Enter a name, an absolute server folder, and a repository URL.");
      return;
    }
    setEditorBusy(true);
    onError(null);
    const before = editorOriginal ? cloneApp(editorOriginal) : null;
    const secretSnapshot = new Map<string, string>();
    const touched: string[] = [];
    const removed: string[] = [];
    try {
      if (before?.id) {
        for (const row of before.env_vars.filter((item) => item.secret && item.has_value)) {
          const value = await vault.deployTransientGet(account(before.id, row.name));
          if (value == null) throw new Error(`The stored value for ${row.name} could not be read. No changes were saved.`);
          secretSnapshot.set(row.name, value);
        }
      }
      const secretValues = editor.env_vars
        .filter((row) => row.secret && row.value.length > 0)
        .map((row) => ({ name: row.name, value: row.value }));
      const payload: DeployAppInput = {
        ...editor,
        name: editor.name.trim(),
        folder: editor.folder.trim(),
        repo: { ...editor.repo, url: editor.repo.url.trim(), branch: editor.repo.branch.trim() || "main" },
        env_vars: editor.env_vars.map((row) => ({
          name: row.name,
          secret: row.secret,
          value: row.secret ? "" : row.value,
          has_value: row.secret ? row.has_value : row.value.length > 0,
        })),
        domains: editor.domains.map((domain) => domain.trim()).filter(Boolean),
      };
      let saved = (await api.deploy.save(payload)).app;
      try {
        for (const secret of secretValues) {
          await vault.set(account(saved.id, secret.name), secret.value);
          await vault.transientForget(account(saved.id, secret.name));
          touched.push(secret.name);
        }
        const keep = new Set(editor.env_vars.filter((row) => row.secret).map((row) => row.name));
        for (const name of (before?.env_vars ?? []).filter((row) => row.secret && row.has_value && !keep.has(row.name)).map((row) => row.name)) {
          await vault.delete(account(saved.id, name));
          removed.push(name);
        }
        if (touched.length) saved = (await api.deploy.secretPresence(saved.id, touched, true)).app;
      } catch (cause) {
        if (before?.id) {
          await api.deploy.save(before);
          const restoredPresent: string[] = [];
          for (const name of new Set([...secretSnapshot.keys(), ...touched, ...removed])) {
            const old = secretSnapshot.get(name);
            if (old == null) await vault.delete(account(before.id, name));
            else {
              await vault.set(account(before.id, name), old);
              restoredPresent.push(name);
            }
          }
          if (restoredPresent.length) await api.deploy.secretPresence(before.id, restoredPresent, true);
        } else {
          for (const name of touched) await vault.delete(account(saved.id, name)).catch(() => undefined);
          await api.deploy.remove(serverId, saved.id);
        }
        throw cause;
      }
      for (const name of secretSnapshot.keys()) await vault.transientForget(account(saved.id, name));
      setEditor(null);
      setEditorOriginal(null);
      setBulkPreview(null);
      setBulkText("");
      await onSaved(saved.id);
    } catch (cause) {
      onError(messageOf(cause));
    } finally {
      setEditorBusy(false);
    }
  };

  return {
    editor,
    setEditor,
    editorBusy,
    bulkText,
    setBulkText,
    bulkPreview,
    openEditor,
    closeEditor,
    previewBulk,
    applyBulkPreview,
    saveEditor,
  };
}
