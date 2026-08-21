// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { ApprovalDialog } from "./features/files/dialogs/ApprovalDialog";
import { TransferDrawer } from "./features/files/TransferDrawer";
import { DeployOutputPane } from "./features/deploy/components/DeployOutputPane";
import { AlertTriangle } from "lucide-react";

describe("A11y Remediation", () => {
  afterEach(() => {
    cleanup();
  });

  describe("ApprovalDialog", () => {
    it("renders with aria-labelledby and aria-describedby linkage", () => {
      const onCancel = vi.fn();
      render(
        <ApprovalDialog
          icon={<AlertTriangle />}
          iconClass="oars-modal-icon-danger"
          title="Delete remote file"
          subtitle="Are you sure you want to delete /var/log/nginx/access.log?"
          actions={<button>Delete</button>}
          onCancel={onCancel}
          labelledBy="test-dialog-title"
        />
      );

      const dialog = screen.getByRole("dialog");
      expect(dialog.getAttribute("aria-labelledby")).toBe("test-dialog-title");
      expect(dialog.getAttribute("aria-describedby")).toBe("test-dialog-title-desc");

      const title = screen.getByText("Delete remote file");
      expect(title.getAttribute("id")).toBe("test-dialog-title");

      const subtitle = screen.getByText("Are you sure you want to delete /var/log/nginx/access.log?");
      expect(subtitle.getAttribute("id")).toBe("test-dialog-title-desc");
    });
  });

  describe("TransferDrawer", () => {
    it("renders accessible progressbar with valuenow and valuetext", () => {
      const onCancelUpload = vi.fn();
      const onCancelTransfer = vi.fn();
      const rows = [
        {
          key: "transfer-1",
          label: "database.sql",
          status: "running" as const,
          bytes: 5000,
          total: 10000,
          upload: 1,
        },
      ];

      render(
        <TransferDrawer
          rows={rows}
          queuedUploads={0}
          onCancelUpload={onCancelUpload}
          onCancelTransfer={onCancelTransfer}
        />
      );

      const progressbar = screen.getByRole("progressbar");
      expect(progressbar).toBeTruthy();
      expect(progressbar.getAttribute("aria-valuenow")).toBe("50");
      expect(progressbar.getAttribute("aria-valuemin")).toBe("0");
      expect(progressbar.getAttribute("aria-valuemax")).toBe("100");
      expect(progressbar.getAttribute("aria-label")).toBe("Transfer progress for database.sql");
      expect(progressbar.getAttribute("aria-valuetext")).toBe("50% (4.9 KB of 9.8 KB)");

      const cancelBtn = screen.getByLabelText("Cancel upload of database.sql");
      expect(cancelBtn).toBeTruthy();
    });
  });

  describe("DeployOutputPane", () => {
    it("renders preformatted output with role=log and live region", () => {
      const onCancel = vi.fn();
      const onClose = vi.fn();
      const steps = [
        {
          id: "step-1",
          label: "Build assets",
          state: "running" as const,
          exit: null,
          error: undefined,
        },
      ];
      const outputs = {
        "step-1": "npm run build output line 1\nline 2",
      };

      render(
        <DeployOutputPane
          runId={42}
          runStatus="running"
          steps={steps}
          outputs={outputs}
          gaps={{}}
          onCancel={onCancel}
          onClose={onClose}
        />
      );

      const log = screen.getByRole("log");
      expect(log).toBeTruthy();
      expect(log.getAttribute("aria-live")).toBe("polite");
      expect(log.getAttribute("aria-atomic")).toBe("false");
      expect(log.getAttribute("tabindex")).toBe("0");
      expect(log.getAttribute("aria-label")).toBe("Output for Build assets");
      expect(log.textContent).toContain("npm run build output line 1");
    });
  });
});
