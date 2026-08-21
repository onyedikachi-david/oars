const body = document.body;
const variant = body.dataset.variant || "focus";
const defaultView = body.dataset.defaultView || "files";
const params = new URLSearchParams(window.location.search);
const view = params.get("view") || defaultView;
const server = params.get("server") || "Production API";

params.delete("view");
params.delete("server");
params.set("concept", variant);

const frame = document.querySelector("#preview-frame");
frame.src = `/preview.html?${params.toString()}`;

frame.addEventListener("load", () => {
  const startedAt = Date.now();
  const openRequestedView = () => {
    const doc = frame.contentDocument;
    if (!doc) return;

    const serverButton = [...doc.querySelectorAll("button")].find((button) =>
      button.textContent?.includes(server) && button.textContent?.includes("api.internal.example"),
    );
    if (serverButton) serverButton.click();

    const viewTab = [...doc.querySelectorAll('[role="tab"]')].find(
      (tab) => tab.textContent?.trim().toLowerCase() === view.toLowerCase(),
    );
    if (viewTab) {
      viewTab.click();
      return;
    }

    if (Date.now() - startedAt < 12_000) window.setTimeout(openRequestedView, 80);
  };

  openRequestedView();
});
