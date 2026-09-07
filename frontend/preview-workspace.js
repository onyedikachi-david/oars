// PROTOTYPE — in-memory only. Promote the winning interaction model by rewriting it in React.
const variants = [
  { id: "tiles", label: "A — Tiled", description: "Drag a server bar to reorder panes. Oars keeps each session active while the layout changes." },
  { id: "canvas", label: "B — Freeform", description: "Move server windows anywhere on the canvas. Their sessions and tools stay independent." },
  { id: "focus", label: "C — Focus + stack", description: "Keep one server large and drag another server into the first position to make it primary." },
];

const servers = [
  { id: "prod-api", name: "Production API", host: "deploy@api.internal.example:22", group: "Production/Core", status: "ready", statusLabel: "Connected", metrics: [38, 46, 61], view: "Monitor" },
  { id: "staging-web", name: "Staging Web", host: "ubuntu@10.24.8.17:2222", group: "Staging", status: "ready", statusLabel: "Connected", metrics: [24, 33, 48], view: "Deploy" },
  { id: "legacy-db", name: "Legacy Database", host: "dba@db-01.internal.example:22", group: "Production/Data", status: "attention", statusLabel: "Needs attention", metrics: [71, 68, 82], view: "Terminal" },
  { id: "edge-cache", name: "Edge Cache", host: "root@edge-03.internal.example:22", group: "Production/Edge", status: "offline", statusLabel: "Offline", metrics: [0, 0, 57], view: "Files" },
];

const state = {
  variant: new URLSearchParams(location.search).get("variant") || "tiles",
  navCollapsed: false,
  openIds: ["prod-api", "staging-web"],
  activeId: "prod-api",
  filter: "",
  views: Object.fromEntries(servers.map((server) => [server.id, server.view])),
  canvasPositions: {
    "prod-api": { x: 18, y: 18, z: 2 },
    "staging-web": { x: 420, y: 90, z: 3 },
    "legacy-db": { x: 120, y: 210, z: 4 },
    "edge-cache": { x: 500, y: 260, z: 5 },
  },
};

if (!variants.some((variant) => variant.id === state.variant)) state.variant = "tiles";

const icons = {
  plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  close: '<svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg>',
};

const grid = document.querySelector("#workspace-grid");
const fleetList = document.querySelector("#fleet-list");
const filterInput = document.querySelector("#fleet-filter");
const paneLimit = document.querySelector("#pane-limit");
const addPaneButton = document.querySelector("#add-pane");
const collapseButton = document.querySelector("#collapse-nav");
const variantLabel = document.querySelector("#variant-label");
const layoutDescription = document.querySelector("#layout-description");
const toast = document.querySelector("#wm-toast");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
let toastTimer = 0;
let dragState = null;

function serverById(id) {
  return servers.find((server) => server.id === id);
}

function setUrlVariant() {
  const params = new URLSearchParams(location.search);
  params.set("variant", state.variant);
  history.replaceState(null, "", `${location.pathname}?${params.toString()}`);
}

function withLayoutTransition(change) {
  if (document.startViewTransition && !reducedMotion.matches) {
    document.startViewTransition(() => {
      change();
      render();
    });
  } else {
    change();
    render();
  }
}

function showToast(message) {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = window.setTimeout(() => { toast.hidden = true; }, 2200);
}

function fleetMarkup() {
  const query = state.filter.trim().toLowerCase();
  const matches = servers.filter((server) => `${server.name} ${server.host} ${server.group}`.toLowerCase().includes(query));
  const groups = [...new Set(matches.map((server) => server.group))];
  return groups.map((group) => `
    <div class="wm-fleet-group">${group}</div>
    ${matches.filter((server) => server.group === group).map((server) => {
      const isOpen = state.openIds.includes(server.id);
      const isActive = state.activeId === server.id;
      return `<button type="button" class="wm-fleet-row ${isOpen ? "is-open" : ""} ${isActive ? "is-active" : ""}" data-server-id="${server.id}" title="${isOpen ? `Focus ${server.name}` : `Open ${server.name} in a new pane`}">
        <i class="wm-status-dot is-${server.status}"></i>
        <span class="wm-fleet-copy"><strong>${server.name}</strong><small>${server.host}</small></span>
        <span class="wm-open-badge">${isOpen ? "Open" : "+"}</span>
      </button>`;
    }).join("")}
  `).join("") || '<div class="wm-fleet-group">No matching servers</div>';
}

function monitorMarkup(server) {
  const [cpu, memory, disk] = server.metrics;
  return `
    <div class="wm-pane-summary"><div><h2>System health</h2><p>Updated just now from the live session.</p></div><span class="wm-health"><i></i>${server.status === "attention" ? "Needs attention" : server.status === "offline" ? "Offline" : "Healthy"}</span></div>
    <div class="wm-metrics"><div class="wm-metric"><span>Uptime</span><strong>${server.id === "staging-web" ? "3d 8h" : "42d 7h"}</strong></div><div class="wm-metric"><span>Load</span><strong>${(cpu / 20).toFixed(2)}</strong></div><div class="wm-metric"><span>Updates</span><strong>${server.id === "legacy-db" ? "7 ready" : "Current"}</strong></div></div>
    <div class="wm-resource-list">
      <div class="wm-resource"><b>CPU</b><span class="wm-resource-track"><i style="--value:${cpu}%"></i></span><span>${cpu}%</span></div>
      <div class="wm-resource"><b>Memory</b><span class="wm-resource-track"><i style="--value:${memory}%"></i></span><span>${memory}%</span></div>
      <div class="wm-resource"><b>Disk</b><span class="wm-resource-track"><i style="--value:${disk}%"></i></span><span>${disk}%</span></div>
    </div>
    <div class="wm-rows"><div class="wm-row"><strong>nginx.service</strong><span>running</span></div><div class="wm-row"><strong>oars-agentless-session</strong><span>ready</span></div><div class="wm-row"><strong>Last backup</strong><span>18 min ago</span></div></div>`;
}

function deployMarkup(server) {
  return `
    <div class="wm-pane-summary"><div><h2>${server.id === "staging-web" ? "Storefront preview" : "API service"}</h2><p>Production application · main</p></div><span class="wm-health"><i></i>Live</span></div>
    <div class="wm-deploy-card"><header><div><h3>Deployment is healthy</h3><p>Commit 52cc437d92 is running on this server.</p></div><span class="wm-health"><i></i>Live</span></header><div class="wm-deploy-meta"><span>Runtime<strong>Node 24</strong></span><span>Last deploy<strong>28 minutes ago</strong></span><span>Branch<strong>main</strong></span><span>Port<strong>3000</strong></span></div><button class="wm-button" type="button">Run preflight</button></div>`;
}

function filesMarkup() {
  return `<div class="wm-pane-summary"><div><h2>Remote files</h2><p>/var/www/current</p></div><span class="wm-health"><i></i>Connected</span></div><div class="wm-rows"><div class="wm-row"><strong>dist</strong><span>folder</span></div><div class="wm-row"><strong>package.json</strong><span>2.4 KB</span></div><div class="wm-row"><strong>.env</strong><span>640 B</span></div><div class="wm-row"><strong>release.zip</strong><span>18.7 MB</span></div></div>`;
}

function terminalMarkup(server) {
  return `<pre class="wm-terminal">Last login: Thu Aug 21 00:14:02
${server.host.split("@")[0]}@${server.name.toLowerCase().replaceAll(" ", "-")}:~$ systemctl --failed
  UNIT                 LOAD   ACTIVE SUB    DESCRIPTION
  backup-prune.service loaded failed failed Remove expired snapshots

1 loaded unit listed.
${server.host.split("@")[0]}@${server.name.toLowerCase().replaceAll(" ", "-")}:~$ <span class="wm-cursor">▋</span></pre>`;
}

function paneContent(server, view) {
  if (view === "Deploy") return deployMarkup(server);
  if (view === "Files") return filesMarkup();
  if (view === "Terminal") return terminalMarkup(server);
  return monitorMarkup(server);
}

function paneMarkup(server, index) {
  const view = state.views[server.id];
  const position = state.canvasPositions[server.id];
  const canvasStyle = state.variant === "canvas" ? `left:${position.x}px;top:${position.y}px;z-index:${position.z};` : "";
  return `<article class="server-pane ${state.activeId === server.id ? "is-active" : ""}" data-pane-id="${server.id}" style="--pane-transition:pane-${server.id};${canvasStyle}">
    <header class="wm-pane-bar">
      <button type="button" class="wm-pane-drag" data-drag-id="${server.id}" aria-label="Move ${server.name} pane">
        <span class="wm-grip" aria-hidden>${"<i></i>".repeat(6)}</span>
        <i class="wm-status-dot is-${server.status}"></i>
        <span class="wm-pane-title"><strong>${server.name}</strong><small>${server.host}</small></span>
      </button>
      <span class="wm-pane-status">${server.statusLabel}</span>
      <button type="button" class="wm-pane-close" data-close-id="${server.id}" aria-label="Close ${server.name} pane" ${state.openIds.length === 1 ? "disabled" : ""}>${icons.close}</button>
    </header>
    <nav class="wm-pane-tabs" aria-label="${server.name} tools">
      ${["Monitor", "Terminal", "Files", "Deploy"].map((tab) => `<button type="button" class="wm-pane-tab ${view === tab ? "is-active" : ""}" data-pane-view="${server.id}:${tab}">${tab}</button>`).join("")}
    </nav>
    <div class="wm-pane-content">${paneContent(server, view)}</div>
  </article>`;
}

function render() {
  document.body.classList.toggle("nav-collapsed", state.navCollapsed);
  collapseButton.setAttribute("aria-label", state.navCollapsed ? "Expand navigation" : "Collapse navigation");
  collapseButton.title = state.navCollapsed ? "Expand navigation" : "Collapse navigation";

  fleetList.innerHTML = fleetMarkup();
  const openServers = state.openIds.map(serverById).filter(Boolean);
  grid.className = `wm-workspace-grid variant-${state.variant} count-${openServers.length}`;
  grid.style.setProperty("--secondary-count", String(Math.max(1, openServers.length - 1)));
  grid.innerHTML = openServers.length
    ? openServers.map(paneMarkup).join("")
    : `<div class="wm-empty-workspace"><div><strong>No server panes open</strong><p>Open a server from the fleet to start a windowed session.</p><button class="wm-button" data-open-first type="button">Open Production API</button></div></div>`;

  paneLimit.textContent = `${openServers.length} of 4 panes`;
  addPaneButton.disabled = openServers.length >= 4;
  addPaneButton.title = openServers.length >= 4 ? "Four panes are already open" : "Open the next server in a pane";
  const variant = variants.find((item) => item.id === state.variant);
  variantLabel.textContent = variant.label;
  layoutDescription.textContent = variant.description;
  setUrlVariant();
  bindRenderedEvents();
}

function openServer(id) {
  if (state.openIds.includes(id)) {
    state.activeId = id;
    if (state.variant === "focus") {
      state.openIds = [id, ...state.openIds.filter((openId) => openId !== id)];
    }
    render();
    return;
  }
  if (state.openIds.length >= 4) {
    showToast("Four server panes are already open. Close one before you add another.");
    return;
  }
  withLayoutTransition(() => {
    state.openIds.push(id);
    state.activeId = id;
  });
}

function closeServer(id) {
  if (state.openIds.length === 1) return;
  withLayoutTransition(() => {
    state.openIds = state.openIds.filter((openId) => openId !== id);
    if (state.activeId === id) state.activeId = state.openIds[0];
  });
}

function addNextServer() {
  const next = servers.find((server) => !state.openIds.includes(server.id));
  if (next) openServer(next.id);
  else showToast("Four server panes are already open.");
}

function setVariant(index) {
  const next = variants[(index + variants.length) % variants.length];
  withLayoutTransition(() => { state.variant = next.id; });
}

function bindRenderedEvents() {
  bindFleetEvents();
  document.querySelectorAll("[data-close-id]").forEach((button) => button.addEventListener("click", () => closeServer(button.dataset.closeId)));
  document.querySelectorAll("[data-pane-view]").forEach((button) => button.addEventListener("click", () => {
    const [id, view] = button.dataset.paneView.split(":");
    state.views[id] = view;
    state.activeId = id;
    render();
  }));
  document.querySelector("[data-open-first]")?.addEventListener("click", () => openServer("prod-api"));
  document.querySelectorAll("[data-drag-id]").forEach((handle) => handle.addEventListener("pointerdown", beginPaneDrag));
}

function bindFleetEvents() {
  document.querySelectorAll("[data-server-id]").forEach((button) => button.addEventListener("click", () => openServer(button.dataset.serverId)));
}

function beginPaneDrag(event) {
  if (event.button !== 0) return;
  const handle = event.currentTarget;
  const id = handle.dataset.dragId;
  const pane = handle.closest(".server-pane");
  const position = state.canvasPositions[id];
  dragState = { id, pane, handle, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, dx: 0, dy: 0, targetId: null, position, frame: 0 };
  handle.setPointerCapture(event.pointerId);
  pane.classList.add("is-dragging");
  state.activeId = id;
  if (state.variant === "canvas") {
    const highest = Math.max(...Object.values(state.canvasPositions).map((entry) => entry.z));
    position.z = highest + 1;
    pane.style.zIndex = String(position.z);
  }
  handle.addEventListener("pointermove", movePane);
  handle.addEventListener("pointerup", endPaneDrag, { once: true });
  handle.addEventListener("pointercancel", endPaneDrag, { once: true });
}

function movePane(event) {
  if (!dragState || event.pointerId !== dragState.pointerId) return;
  dragState.dx = event.clientX - dragState.startX;
  dragState.dy = event.clientY - dragState.startY;
  if (dragState.frame) return;
  dragState.frame = requestAnimationFrame(() => {
    if (!dragState) return;
    dragState.frame = 0;
    dragState.pane.style.transform = `translate3d(${dragState.dx}px, ${dragState.dy}px, 0)`;
    if (state.variant !== "canvas") {
      dragState.pane.style.pointerEvents = "none";
      const target = document.elementFromPoint(event.clientX, event.clientY)?.closest(".server-pane");
      dragState.pane.style.pointerEvents = "";
      document.querySelectorAll(".is-drop-target").forEach((element) => element.classList.remove("is-drop-target"));
      if (target && target.dataset.paneId !== dragState.id) {
        dragState.targetId = target.dataset.paneId;
        target.classList.add("is-drop-target");
      } else {
        dragState.targetId = null;
      }
    }
  });
}

function endPaneDrag(event) {
  if (!dragState || event.pointerId !== dragState.pointerId) return;
  const current = dragState;
  if (state.variant !== "canvas") {
    current.pane.style.pointerEvents = "none";
    const releaseTarget = document.elementFromPoint(event.clientX, event.clientY)?.closest(".server-pane");
    current.pane.style.pointerEvents = "";
    if (releaseTarget && releaseTarget.dataset.paneId !== current.id) {
      current.targetId = releaseTarget.dataset.paneId;
    }
  }
  if (current.frame) cancelAnimationFrame(current.frame);
  current.handle.removeEventListener("pointermove", movePane);
  current.pane.classList.remove("is-dragging");
  document.querySelectorAll(".is-drop-target").forEach((element) => element.classList.remove("is-drop-target"));

  if (state.variant === "canvas") {
    const board = grid.getBoundingClientRect();
    const paneRect = current.pane.getBoundingClientRect();
    current.position.x = Math.max(8, Math.min(board.width - paneRect.width - 8, current.position.x + current.dx));
    current.position.y = Math.max(8, Math.min(board.height - paneRect.height - 8, current.position.y + current.dy));
    current.pane.style.left = `${current.position.x}px`;
    current.pane.style.top = `${current.position.y}px`;
    current.pane.style.transform = "";
    current.pane.classList.add("is-active");
  } else if (current.targetId) {
    const sourceIndex = state.openIds.indexOf(current.id);
    const targetIndex = state.openIds.indexOf(current.targetId);
    current.pane.style.transform = "";
    dragState = null;
    withLayoutTransition(() => {
      const reordered = [...state.openIds];
      reordered.splice(sourceIndex, 1);
      reordered.splice(targetIndex, 0, current.id);
      state.openIds = reordered;
      state.activeId = current.id;
    });
    return;
  } else {
    current.pane.animate(
      [{ transform: current.pane.style.transform }, { transform: "translate3d(0, 0, 0)" }],
      { duration: reducedMotion.matches ? 1 : 260, easing: "cubic-bezier(0.16, 1, 0.3, 1)" },
    );
    current.pane.style.transform = "";
  }
  dragState = null;
}

collapseButton.addEventListener("click", () => {
  if (innerWidth <= 820) {
    document.body.classList.toggle("mobile-nav-open");
    return;
  }
  state.navCollapsed = !state.navCollapsed;
  document.body.classList.toggle("nav-collapsed", state.navCollapsed);
  collapseButton.setAttribute("aria-label", state.navCollapsed ? "Expand navigation" : "Collapse navigation");
  collapseButton.title = state.navCollapsed ? "Expand navigation" : "Collapse navigation";
});

document.querySelector(".wm-breadcrumbs").addEventListener("click", () => {
  if (innerWidth <= 820) document.body.classList.add("mobile-nav-open");
});
filterInput.addEventListener("input", (event) => { state.filter = event.target.value; fleetList.innerHTML = fleetMarkup(); bindFleetEvents(); });
addPaneButton.addEventListener("click", addNextServer);
document.querySelector("#previous-variant").addEventListener("click", () => setVariant(variants.findIndex((variant) => variant.id === state.variant) - 1));
document.querySelector("#next-variant").addEventListener("click", () => setVariant(variants.findIndex((variant) => variant.id === state.variant) + 1));

window.addEventListener("keydown", (event) => {
  const target = event.target;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target.isContentEditable) return;
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  event.preventDefault();
  const index = variants.findIndex((variant) => variant.id === state.variant);
  setVariant(index + (event.key === "ArrowRight" ? 1 : -1));
});

render();
