import { githubUrl } from "../downloads";
import "./roadmap.css";

const alerts = [
  { title: "Crashes & restarts", description: "A monitored process exits unexpectedly or keeps restarting." },
  { title: "Resource pressure", description: "CPU or memory stays high, or disk space and inodes run low." },
  { title: "Connection changes", description: "A server stops responding, disconnects, or comes back online." },
  { title: "Jobs & transfers", description: "A deployment, script, backup, or file transfer fails or finishes." },
  { title: "Certificate expiry", description: "A server’s TLS certificate is getting close to its expiry date." },
  { title: "Security changes", description: "A host key or server access changes, or repeated login failures are detected." },
];
type IconName = "windows" | "bell" | "tunnel" | "shield" | "process" | "ai" | "team" | "terminal" | "plugin" | "mobile" | "arrow";
const planned: { icon: IconName; title: string; description: string }[] = [
  { icon: "tunnel", title: "SSH tunnels", description: "Saved local, remote, and SOCKS tunnels for databases and private services." },
  { icon: "shield", title: "Security reports", description: "Hardening checks, suggested fixes, and exportable reports." },
  { icon: "process", title: "Process management", description: "Inspect, restart, reload, and stop PM2 processes and system services." },
  { icon: "ai", title: "AI web search & MCP", description: "Current documentation and external tools in reviewed AI workflows." },
];
const exploring: { icon: IconName; title: string; description: string }[] = [
  { icon: "team", title: "Team workspaces", description: "Encrypted sync, shared vaults, terminal collaboration, SSO, and two-factor controls." },
  { icon: "terminal", title: "More connections", description: "Local shells, serial connections, Telnet, and X11 forwarding." },
  { icon: "plugin", title: "Plugins", description: "Add tools and adapt Oars to the way you work." },
  { icon: "mobile", title: "Mobile & browser", description: "Reach your servers from a phone, tablet, or browser." },
];
function RoadmapIcon({ name }: { name: IconName }) {
  const paths: Record<IconName, string> = {
    windows: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    bell: "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4",
    tunnel: "M4 8h16m-4-4 4 4-4 4M20 16H4m4-4-4 4 4 4",
    shield: "m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6",
    process: "M3 12h4l3-8 4 16 3-8h4",
    ai: "M8 7h8a3 3 0 0 1 3 3v7H5v-7a3 3 0 0 1 3-3ZM12 3v4M9 11v2m6-2v2M2 11v3m20-3v3M9 20h6",
    team: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM17 4a4 4 0 0 1 0 7m5 10v-2a4 4 0 0 0-3-4",
    terminal: "M3 4h18v16H3zM7 9l3 3-3 3m6 0h4",
    plugin: "M8 3v5m8-5v5M6 8h12v4a6 6 0 0 1-12 0zM12 18v4",
    mobile: "M7 2h10v20H7zM11 18h2",
    arrow: "M5 12h14m-6-6 6 6-6 6",
  };
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>;
}

function FeatureCard({ item }: { item: typeof planned[number] }) {
  return <li className="roadmap-card"><div className="roadmap-card-title"><RoadmapIcon name={item.icon} /><h4>{item.title}</h4></div><p>{item.description}</p></li>;
}

export function Roadmap() {
  return <section className="section roadmap-section" id="roadmap" aria-labelledby="roadmap-title">
    <div className="section-heading roadmap-heading">
      <div><span className="section-label">The road ahead</span><h2 id="roadmap-title">What’s next for Oars.</h2></div>
      <p>Upcoming features and ideas we’re exploring.<br />Not available yet. No release dates set.</p>
    </div>
    <div className="roadmap-board">
      <section className="roadmap-lane roadmap-lane--next" aria-labelledby="roadmap-next">
        <header className="roadmap-lane-heading"><div><span className="roadmap-stage-dot" aria-hidden="true" /><h3 id="roadmap-next">Coming next</h3><span className="roadmap-count">2</span></div><p>Our next priorities.</p></header>
        <ul className="roadmap-cards">
          <li className="roadmap-card roadmap-card--featured"><div className="roadmap-card-title"><RoadmapIcon name="windows" /><h4>Oars for Windows</h4></div><p>Your Linux servers, in one workspace on your Windows PC.</p><div className="roadmap-platform-note">macOS & Linux are available today.</div></li>
          <li className="roadmap-card roadmap-card--featured"><div className="roadmap-card-title"><RoadmapIcon name="bell" /><h4>Desktop notifications</h4></div><p>Know when a server or job needs your attention while Oars is connected.</p><div className="roadmap-tags" aria-label="Planned notification controls"><span>Thresholds</span><span>Quiet hours</span><span>Grouped alerts</span></div>
            <details className="roadmap-alert-details"><summary><span>6 types of alerts</span><span className="roadmap-chevron" aria-hidden="true" /></summary><ul>{alerts.map(alert => <li key={alert.title}><strong>{alert.title}</strong><p>{alert.description}</p></li>)}</ul></details>
          </li>
        </ul>
      </section>
      <section className="roadmap-lane" aria-labelledby="roadmap-planned">
        <header className="roadmap-lane-heading"><div><span className="roadmap-stage-dot" aria-hidden="true" /><h3 id="roadmap-planned">Planned</h3><span className="roadmap-count">4</span></div><p>More control over your servers.</p></header>
        <ul className="roadmap-cards">{planned.map(item => <FeatureCard key={item.title} item={item} />)}</ul>
      </section>
      <section className="roadmap-lane roadmap-lane--exploring" aria-labelledby="roadmap-exploring">
        <header className="roadmap-lane-heading"><div><span className="roadmap-stage-dot" aria-hidden="true" /><h3 id="roadmap-exploring">Exploring</h3><span className="roadmap-count">4</span></div><p>Longer-term possibilities.</p></header>
        <ul className="roadmap-cards">{exploring.map(item => <FeatureCard key={item.title} item={item} />)}</ul>
      </section>
    </div>
    <div className="roadmap-feedback"><p>Help shape what comes next.</p><a className="inline-link" href={`${githubUrl}/issues`}>Suggest a feature on GitHub <RoadmapIcon name="arrow" /></a></div>
  </section>;
}
