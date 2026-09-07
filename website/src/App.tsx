import { useState } from "react";
import { ProductShot, ScreenshotGallery } from "./components/ProductScreenshots";
import { downloads, githubUrl, sponsorUrl } from "./downloads";
import "./landing.css";

function Icon({ name }: { name: "download" | "star" | "arrow" | "terminal" | "desktop" | "files" }) {
  const paths = {
    download: "M12 3v12m-5-5 5 5 5-5M5 16v4h14v-4",
    star: "m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9Z",
    arrow: "M5 12h14m-6-6 6 6-6 6",
    terminal: "m5 6 5 6-5 6m8 0h6",
    desktop: "M3 4h18v13H3ZM12 17v4m-4 0h8",
    files: "M3 6h7l2 3h9v11H3Zm0 0V3h7l2 3h7v3",
  };
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>;
}
function DownloadButtons() {
  return <div className="download-buttons"><a className="cta cta-primary" href={downloads.macos}><Icon name="download" />Download for macOS</a><a className="cta cta-secondary" href={downloads.linux}><Icon name="download" />Download for Linux</a></div>;
}
const modes = [
  { id: "files", title: "Files & operations", icon: "files", shot: "files", caption: "Your files. Both sides of the connection." },
  { id: "logs", title: "Logs & history", icon: "terminal", shot: "logs", caption: "From a log line to the answer you need." },
  { id: "desktop", title: "Remote desktop", icon: "desktop", shot: "desktop", caption: "A Linux desktop, right inside your workspace." },
] as const;

export default function App() {
  const [selected, setSelected] = useState(0);
  const active = modes[selected];
  return <>
    <a className="skip-link" href="#main">Skip to content</a>
    <header className="site-nav">
      <a href="#" className="site-brand" aria-label="Oars home"><img src="/brand/oars-symbol.svg" width="36" height="36" alt="" />Oars</a>
      <nav aria-label="Main navigation"><a href="#features">Product</a><a href="#pictures">In pictures</a><a href="#faq">FAQ</a></nav>
      <div className="nav-actions"><a className="star-link" href={githubUrl} aria-label="Star Oars on GitHub"><Icon name="star" /><span>Star on GitHub</span></a><a className="cta cta-small" href="#download">Download</a></div>
    </header>
    <main id="main">
      <section className="hero" aria-labelledby="hero-title">
        <div className="mode-picker" role="group" aria-label="Choose a workspace preview">{modes.map((mode, i) => <button key={mode.id} aria-pressed={selected === i} aria-controls="hero-preview" onClick={() => setSelected(i)}><Icon name={mode.icon} />{mode.title}</button>)}</div>
        <h1 id="hero-title">Your servers.<br />One calm workspace.</h1>
        <p className="hero-intro">Everything you need to work with your Linux servers.<br className="desktop-break" /> Terminals, files, logs, and remote desktops, together in one open source app.</p>
        <DownloadButtons />
        <p className="hero-note">Free and open source · macOS & Linux</p>
        <div id="hero-preview" className="hero-preview"><ProductShot key={active.shot} name={active.shot} caption={false} priority /><p aria-live="polite">{active.caption}</p></div>
      </section>

      <section className="section intro-section" id="features">
        <div className="section-heading"><h2>Less switching.<br />More getting things done.</h2><p>Connect once and keep the whole job in view. Follow a log, move a file, run a command, or check on another server without losing your place.</p></div>
        <div className="feature-strip"><div><Icon name="terminal" /><h3>Connect your way</h3><p>SSH keys, passwords, agents, and jump hosts. Your existing servers, ready to work.</p></div><div><Icon name="files" /><h3>Keep the tools together</h3><p>Interactive shells, SFTP, live metrics, logs, scripts, deployments, and backups.</p></div><div><Icon name="desktop" /><h3>Make room for your fleet</h3><p>Organize servers into groups and arrange sessions in tabs or split panes.</p></div></div>
      </section>

      <section className="feature-section section">
        <div className="feature-copy"><span className="section-label">See what’s happening</span><h2>Go from “what broke?”<br />to the useful details.</h2><p>Check CPU, memory, disks, and processes. Find the right log, search its output, and follow new lines as they arrive.</p><ul><li>Agentless server monitoring</li><li>Searchable logs and local command history</li><li>Saved scripts for repeatable operations</li></ul><a className="inline-link" href="#pictures">Explore the workspace <Icon name="arrow" /></a></div>
        <div className="feature-image feature-image-blue"><ProductShot name="logs" caption={false} /></div>
      </section>

      <section className="feature-section feature-section-reverse section">
        <div className="feature-copy"><span className="section-label">Beyond the terminal</span><h2>A whole desktop.<br />Still one connection.</h2><p>Open a remote Linux desktop through an SSH tunnel. Fit it to your window, share clipboard text, or go full screen when you need more room.</p><ul><li>VNC carried through your SSH connection</li><li>Window scaling and full-screen controls</li><li>Desktop setup and start controls</li></ul><a className="inline-link" href="#download">Get Oars <Icon name="arrow" /></a></div>
        <div className="feature-image feature-image-sand"><ProductShot name="desktop" caption={false} /></div>
      </section>

      <section className="pictures-section" id="pictures"><div className="section"><div className="section-heading centered"><span className="section-label">The app, at work</span><h2>In pictures</h2><p>Take a look around before you connect your first server.</p></div><ScreenshotGallery /></div></section>

      <section className="section ownership"><div><span className="section-label">Open source. Local first.</span><h2>Your infrastructure.<br />Your way of working.</h2><p>Oars connects directly to your servers over SSH. Connection credentials use your OS credential store, and profiles and history live on your device.</p><p>AI assistance is optional. Choose your provider, review the context you share, and approve proposed commands before they run.</p></div><div className="community-panel"><Icon name="star" /><h3>Built in the open.<br />Better with you.</h3><p>Found Oars useful? Give it a star, report a bug, or help build what comes next.</p><a className="cta cta-primary" href={githubUrl}><Icon name="star" />Star Oars on GitHub</a><a className="inline-link" href={sponsorUrl}>Sponsor development <Icon name="arrow" /></a></div></section>

      <section className="section faq-section" id="faq"><div><span className="section-label">Good to know</span><h2>A few questions,<br />before you connect.</h2><a className="inline-link" href={`${githubUrl}/issues`}>Ask on GitHub <Icon name="arrow" /></a></div><div className="faq-list">
        <details><summary>Is Oars free?</summary><p>Yes. Oars is open source under the MIT license. You can use it, inspect the code, and contribute. Sponsorship is optional.</p></details>
        <details><summary>Do I need an account to download it?</summary><p>No GitHub account is needed to download a public release. The download buttons link directly to the release files. GitHub Actions artifacts are separate and require a GitHub account.</p></details>
        <details><summary>Which operating systems are supported?</summary><p>Oars runs on macOS and Linux and manages Linux servers over SSH. The Linux download is for x86_64 and requires GTK4 and WebKitGTK 6.0. Windows is not currently supported.</p></details>
        <details><summary>Do I need to install an agent on my servers?</summary><p>Terminal access, files, logs, and monitoring use SSH without a separate Oars agent. Some features need remote tools, such as rclone for backups and a VNC server with a desktop environment for remote desktop access.</p></details>
        <details><summary>Why does macOS show a security prompt?</summary><p>Oars is currently unsigned and not notarized. If you trust the download, follow <a href="https://support.apple.com/guide/mac-help/mh40616/mac">Apple’s instructions for opening an unidentified app</a>.</p></details>
      </div></section>

      <section className="download-section" id="download"><img src="/brand/oars-symbol.svg" width="64" height="64" alt="" /><h2>Bring your servers together.</h2><p>A little less juggling. A lot more room to work.</p><DownloadButtons /><p className="download-meta">Latest release · macOS ZIP · Linux x86_64 tar.gz</p><a className="inline-link" href={`${githubUrl}/releases`}>Release notes & checksums <Icon name="arrow" /></a></section>
    </main>
    <footer className="site-footer"><div><a className="site-brand" href="#"><img src="/brand/oars-symbol.svg" width="30" height="30" alt="" />Oars</a><p>Your Linux servers, in one local window.</p></div><nav aria-label="Footer navigation"><a href="#download">Download</a><a href={githubUrl}>Star on GitHub</a><a href={sponsorUrl}>Sponsor</a><a href={`${githubUrl}/blob/main/LICENSE`}>MIT license</a></nav></footer>
  </>;
}
