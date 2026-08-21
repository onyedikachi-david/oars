import { Plus, Rocket, X, XCircle } from "lucide-react";
import { Button } from "../../components/ui/button";
import { OarsLoadingState } from "../../components/OarsLoadingState";
import { DeleteDialog } from "./components/DeleteDialog";
import { DeployDetailView } from "./components/DeployDetailView";
import { DeployEditorModal } from "./components/DeployEditorModal";
import { DeployListRail } from "./components/DeployListRail";
import { DeployOutputPane } from "./components/DeployOutputPane";
import { PreflightInspector } from "./components/PreflightInspector";
import { useDeployDelete } from "./hooks/useDeployDelete";
import { useDeployEditor } from "./hooks/useDeployEditor";
import { useDeployList } from "./hooks/useDeployList";
import { useDeployPreflight } from "./hooks/useDeployPreflight";
import { useDeployRun } from "./hooks/useDeployRun";
import type { DeployTabProps } from "./types";
import { terminalStatuses } from "./utils";

export function DeployTab({ serverId, initialAppId, onAppsLoaded, onClearPendingApp }: DeployTabProps) {
  const { runId, runAppId, runStatus, steps, outputs, gaps, startRun, requestCancel, resetRun } =
    useDeployRun(serverId, (appId) => void loadHistory(appId), (err) => setError(err));

  const { apps, selected, setSelectedId, history, loading, hasLoaded, error, setError, load, loadHistory, selectApp } =
    useDeployList(serverId, initialAppId, onAppsLoaded, onClearPendingApp, runId, runAppId, runStatus, resetRun);

  const {
    preflight,
    preflightBusy,
    repoActionBusy,
    deployPublicKey,
    approvals,
    secretInputs,
    startPreflight,
    cancelPreflight,
    createDeployKey,
    trustGitHost,
    setApprovals,
    setSecretInputs,
  } = useDeployPreflight(serverId, selected, setError);

  const {
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
  } = useDeployEditor(serverId, async (savedId) => {
    await load();
    setSelectedId(savedId);
  }, setError);

  const { deleteState, openDelete, closeDelete, confirmDelete } = useDeployDelete(serverId, load);

  const latest = (history ?? [])[0] ?? null;
  const activeRun = runId != null && runAppId === selected?.id;
  const displayStatus = activeRun && !terminalStatuses.has(runStatus) ? runStatus : latest?.status ?? "idle";

  if (loading && !hasLoaded) {
    return <OarsLoadingState title="Loading deployments" detail="Oars is reading the applications configured for this server." />;
  }

  return (
    <section className="deploy-workspace" aria-label="Deployments">
      <DeployListRail
        apps={apps}
        selectedId={selected?.id ?? null}
        loading={loading}
        onSelectApp={selectApp}
        onNewApp={() => openEditor()}
        onRefresh={() => void load()}
      />

      <div className="deploy-main">
        {error && (
          <div className="deploy-alert is-error" role="alert">
            <XCircle />
            <span>{error}</span>
            <Button size="icon-xs" variant="ghost" aria-label="Dismiss error" onClick={() => setError(null)}>
              <X />
            </Button>
          </div>
        )}

        {!selected ? (
          <div className="deploy-empty">
            <Rocket />
            <h2>Prepare your first application</h2>
            <p>Save a repository, review live server checks, and deploy the exact approved plan.</p>
            <Button onClick={() => openEditor()}><Plus />New application</Button>
          </div>
        ) : (
          <>
            <DeployDetailView
              app={selected}
              displayStatus={displayStatus}
              latest={latest}
              history={history}
              onEdit={() => openEditor(selected)}
              onDelete={() => openDelete(selected)}
              onRefreshHistory={() => void loadHistory(selected.id)}
            />

            <PreflightInspector
              app={selected}
              preflight={preflight}
              preflightBusy={preflightBusy}
              repoActionBusy={repoActionBusy}
              deployPublicKey={deployPublicKey}
              approvals={approvals}
              secretInputs={secretInputs}
              isRunActive={runId != null && !terminalStatuses.has(runStatus)}
              onStartPreflight={() => void startPreflight()}
              onCancelPreflight={() => void cancelPreflight()}
              onCreateDeployKey={() => void createDeployKey()}
              onTrustGitHost={() => void trustGitHost()}
              onToggleApproval={(id, checked) => setApprovals((prev) => ({ ...prev, [id]: checked }))}
              onChangeSecret={(name, val) => setSecretInputs((prev) => ({ ...prev, [name]: val }))}
              onStartRun={() => preflight && void startRun(selected, preflight, approvals, secretInputs)}
            />

            {activeRun && (
              <DeployOutputPane
                runId={runId}
                runStatus={runStatus}
                steps={steps}
                outputs={outputs}
                gaps={gaps}
                onCancel={() => void requestCancel()}
                onClose={resetRun}
              />
            )}
          </>
        )}
      </div>

      {editor && (
        <DeployEditorModal
          editor={editor}
          setEditor={setEditor}
          busy={editorBusy}
          error={error}
          bulkText={bulkText}
          setBulkText={setBulkText}
          bulkPreview={bulkPreview}
          onPreview={previewBulk}
          onApplyPreview={applyBulkPreview}
          onCancel={closeEditor}
          onSave={() => void saveEditor()}
        />
      )}

      {deleteState && (
        <DeleteDialog
          state={deleteState}
          onCancel={closeDelete}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </section>
  );
}
