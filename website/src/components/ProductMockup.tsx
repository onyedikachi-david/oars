import "./ProductMockup.css";

type ProductView = "fleet" | "terminal" | "deploy";

type ProductMockupProps = {
  view?: ProductView;
  compact?: boolean;
};

const navItems = ["Fleet", "Terminal", "Files", "Monitor", "Deploy"] as const;
const servers = [
  { name: "web-01", host: "10.24.8.11", status: "ready" },
  { name: "worker-02", host: "10.24.8.18", status: "ready" },
  { name: "postgres", host: "10.24.8.31", status: "watch" },
] as const;

function FleetView() {
  return (
    <section className="product-mockup__content">
      <div className="product-mockup__heading">
        <div><h2>Fleet overview</h2><p>Three Linux hosts over direct SSH</p></div>
        <span className="product-mockup__action">Add server</span>
      </div>
      <div className="product-mockup__metrics">
        <div><small>Online</small><b>3 / 3</b><i className="is-green" /></div>
        <div><small>Average load</small><b>0.42</b><span>stable</span></div>
        <div><small>Disk pressure</small><b>18%</b><span>healthy</span></div>
      </div>
      <div className="product-mockup__panels">
        <article className="product-mockup__panel product-mockup__chart-panel">
          <header><div><b>Resource monitor</b><small>Agentless remote probes</small></div><span>Last 30 min</span></header>
          <div className="product-mockup__chart" aria-hidden="true">
            <svg viewBox="0 0 500 154">
              <path className="grid" d="M0 28H500M0 77H500M0 126H500" />
              <path className="memory" d="M0 103 C45 98 70 111 112 91 S190 73 231 83 S302 110 349 86 S430 60 500 67" />
              <path className="cpu" d="M0 119 C32 110 61 114 96 105 S150 111 182 88 S237 98 276 74 S329 98 374 73 S435 84 500 48" />
            </svg>
          </div>
          <footer><span><i className="is-green" />CPU</span><span><i className="is-brass" />Memory</span></footer>
        </article>
        <article className="product-mockup__panel product-mockup__processes">
          <header><div><b>Top processes</b><small>web-01</small></div><span>CPU</span></header>
          <div><code>node server.js</code><b>12.4%</b></div>
          <div><code>postgres</code><b>8.1%</b></div>
          <div><code>caddy run</code><b>2.7%</b></div>
          <div><code>systemd</code><b>0.4%</b></div>
        </article>
      </div>
    </section>
  );
}

function TerminalView() {
  return (
    <section className="product-mockup__terminal-wrap">
      <div className="product-mockup__terminal-head">
        <div><i /><span><b>web-01</b><small>root@10.24.8.11</small></span></div><span>Connected via SSH</span>
      </div>
      <div className="product-mockup__tabs"><span className="is-active">Terminal</span><span>Files</span><span>Monitor</span><span>Logs</span></div>
      <pre className="product-mockup__terminal"><span className="prompt">root@web-01</span>:<span className="path">~</span>$ systemctl status oars-web{"\n"}<span className="success">●</span> oars-web.service, Oars web application{"\n"}   Loaded: loaded (/etc/systemd/system/oars-web.service; enabled){"\n"}   Active: <span className="success">active (running)</span> since Fri 09:42:14 UTC{"\n"} Main PID: 1842 (node){"\n"}    Tasks: 23{"\n"}   Memory: 148.6M{"\n"}      CPU: 4min 12.903s{"\n\n"}<span className="prompt">root@web-01</span>:<span className="path">~</span>$ tail -f /var/log/oars/access.log{"\n"}10.24.8.44 GET /health <span className="success">200</span> 8ms{"\n"}10.24.8.44 GET /api/fleet <span className="success">200</span> 31ms{"\n"}<span className="prompt">root@web-01</span>:<span className="path">~</span>$ <span className="cursor"> </span></pre>
    </section>
  );
}

function DeployView() {
  return (
    <section className="product-mockup__content">
      <div className="product-mockup__heading"><div><h2>Deployments</h2><p>Git releases with streamed output</p></div><span className="product-mockup__action">New deployment</span></div>
      <article className="product-mockup__release">
        <div className="product-mockup__release-top"><span className="product-mockup__release-icon">↗</span><div><small>Deploying to web-01</small><b>oars-web / main</b><p>commit 8f19d2a · started by you</p></div><span className="product-mockup__live">Running</span></div>
        <div className="product-mockup__steps">
          <div className="is-done"><i>✓</i><span><b>Connect</b><small>Host verified</small></span><time>0.4s</time></div>
          <div className="is-done"><i>✓</i><span><b>Fetch</b><small>Repo updated</small></span><time>1.8s</time></div>
          <div className="is-running"><i /><span><b>Build</b><small>npm run build</small></span><time>12s</time></div>
          <div><i /><span><b>Restart</b><small>systemctl restart</small></span><time>queued</time></div>
        </div>
        <pre>$ npm run build{"\n"}✓ 142 modules transformed{"\n"}rendering chunks...{"\n"}<span>dist/index.html     2.14 kB</span></pre>
      </article>
    </section>
  );
}

export function ProductMockup({ view = "fleet", compact = false }: ProductMockupProps) {
  const title = view === "fleet" ? "Fleet overview" : view === "terminal" ? "web-01 terminal" : "Deployments";

  return (
    <figure className={`product-mockup${compact ? " is-compact" : ""}`} aria-label={`Oars ${view} interface preview`}>
      <aside className="product-mockup__sidebar">
        <div className="product-mockup__brand"><img src="/brand/oars-symbol.svg" width="28" height="28" alt="" /><strong>Oars</strong></div>
        <div className="product-mockup__workspace"><span className="product-mockup__workspace-mark">P</span><span><b>Production</b><small>3 servers</small></span></div>
        <nav aria-label="Product preview navigation">
          {navItems.map((item) => <span className={`product-mockup__nav-item${item.toLowerCase() === view ? " is-active" : ""}`} key={item}><i aria-hidden="true" />{item}</span>)}
        </nav>
        <div className="product-mockup__fleet"><p>Servers</p>{servers.map((server) => <div className="product-mockup__server" key={server.name}><i className={`is-${server.status}`} /><span><b>{server.name}</b><small>{server.host}</small></span></div>)}</div>
        <div className="product-mockup__local"><i /><span><b>Local vault</b><small>Credentials on device</small></span></div>
      </aside>
      <div className="product-mockup__main">
        <header className="product-mockup__topbar"><div><span>Production</span><b>/</b><strong>{title}</strong></div><span className="product-mockup__shortcut">⌘ K</span></header>
        {view === "fleet" ? <FleetView /> : view === "terminal" ? <TerminalView /> : <DeployView />}
      </div>
    </figure>
  );
}
