/*
THESIS: Oars is understood as a five-stage operator workflow, not a catalog of disconnected utilities.
OWN-WORLD: Warm mineral paper, graphite command surfaces, brass state cues, ruled records, and compact technical metadata.
STORY: Connect a host, establish trust, observe its state, operate directly, and recover with local records.
FIRST VIEWPORT: A decisive product promise sits beside a linked runbook index, with the GitHub action always visible.
FORM: Narrative Workflow, position 3, staged as an operations runbook with Operate carrying the focused product view.
*/
import { ProductShot, ScreenshotGallery } from "./components/ProductScreenshots";
import { ArrowDownIcon } from "./components/icons/arrow-down";
import { ArrowDownRightIcon } from "./components/icons/arrow-down-right";
import { ArrowUpRightIcon } from "./components/icons/arrow-up-right";
import { GithubIcon } from "./components/icons/github";
import "./workflow.css";
import "./components/ProductScreenshots.css";

const githubUrl = "https://github.com/onyedikachi-david/oars";

const workflowSteps = [
  ["01", "Connect", "Connection profile"],
  ["02", "Trust", "Host verification"],
  ["03", "Observe", "Live remote state"],
  ["04", "Operate", "Daily control"],
  ["05", "Recover", "Local history"],
] as const;

export default function App() {
  return (
    <div className="operator-workflow">
      <header className="operator-workflow__nav">
        <a className="operator-workflow__brand" href="#top" aria-label="Oars home">
          <img src="/brand/oars-symbol.svg" width="32" height="32" alt="" />
          <span>Oars</span>
        </a>

        <nav className="operator-workflow__command" aria-label="Workflow navigation">
          <span className="operator-workflow__command-path" aria-hidden="true">oars / workflow</span>
          {workflowSteps.map(([number, title]) => (
            <a href={`#${title.toLowerCase()}`} key={title}>
              <span>{number}</span> {title}
            </a>
          ))}
        </nav>

        <a className="operator-workflow__source" href={githubUrl}>
          <GithubIcon className="operator-workflow__icon" size={16} aria-hidden="true" />
          GitHub
        </a>
      </header>

      <main id="top">
        <section className="operator-workflow__hero">
          <div className="operator-workflow__hero-copy">
            <h1>Operate every Linux server from one local window.</h1>
            <p>Terminals, files, logs, monitoring, deployments, access, backups, and remote desktop over SSH. Connection credentials are stored in your OS credential store.</p>
            <div className="operator-workflow__hero-actions">
              <a className="operator-workflow__button operator-workflow__button--primary" href={githubUrl}>
                <GithubIcon className="operator-workflow__icon" size={18} aria-hidden="true" />
                View on GitHub
              </a>
              <a className="operator-workflow__button operator-workflow__button--quiet" href="#connect">
                Start the workflow
                <ArrowDownIcon className="operator-workflow__icon" size={17} aria-hidden="true" />
              </a>
            </div>
          </div>

          <ol className="operator-workflow__route" aria-label="Oars operator workflow">
            {workflowSteps.map(([number, title, detail]) => (
              <li key={title}>
                <a href={`#${title.toLowerCase()}`}>
                  <span>{number}</span>
                  <strong>{title}</strong>
                  <small>{detail}</small>
                  <ArrowDownRightIcon className="operator-workflow__route-icon" size={15} aria-hidden="true" />
                </a>
              </li>
            ))}
          </ol>

          <div className="operator-workflow__facts" aria-label="Oars product facts">
            <span>Local-first desktop</span>
            <span>Direct SSH</span>
            <span>Agentless monitoring</span>
            <span>Open source</span>
          </div>
          <div className="operator-workflow__hero-product"><ProductShot name="desktop" priority /></div>
        </section>

        <section className="operator-workflow__stage" id="connect">
          <div className="operator-workflow__stage-inner">
            <div className="operator-workflow__stage-index"><span>01</span><small>of 05</small></div>
            <div className="operator-workflow__stage-copy">
              <h2>Connect</h2>
              <p>Save the host, port, user, and authentication method. Oars connects directly over SSH without introducing a hosted control plane.</p>
            </div>

            <div className="operator-workflow__proof operator-workflow__connection" aria-label="Oars connection profile preview">
              <div className="operator-workflow__proof-heading">
                <div><strong>Connection profile</strong><span>New Linux host</span></div>
                <span>Direct SSH</span>
              </div>
              <dl className="operator-workflow__field-grid">
                <div><dt>Name</dt><dd>web-01</dd></div>
                <div><dt>Host</dt><dd>10.24.8.11</dd></div>
                <div><dt>Port</dt><dd>22</dd></div>
                <div><dt>User</dt><dd>root</dd></div>
              </dl>
              <div className="operator-workflow__proof-action"><span>Authentication</span><strong>SSH key</strong><b>Verify connection</b></div>
            </div>
          </div>
        </section>

        <section className="operator-workflow__stage operator-workflow__stage--tinted" id="trust">
          <div className="operator-workflow__stage-inner">
            <div className="operator-workflow__stage-index"><span>02</span><small>of 05</small></div>
            <div className="operator-workflow__stage-copy">
              <h2>Trust</h2>
              <p>Oars verifies the SSH host key before trust is stored. Credentials stay in your OS credential store, not in server configuration files.</p>
            </div>

            <div className="operator-workflow__proof operator-workflow__trust" aria-label="Oars host verification preview">
              <div className="operator-workflow__proof-heading">
                <div><strong>Host key verification</strong><span>web-01 · 10.24.8.11</span></div>
                <span>Review required</span>
              </div>
              <dl className="operator-workflow__record-list">
                <div><dt>Host key</dt><dd>Review fingerprint</dd></div>
                <div><dt>Credentials</dt><dd>OS credential store</dd></div>
                <div><dt>Trust</dt><dd>Saved only after approval</dd></div>
              </dl>
            </div>
          </div>
        </section>

        <section className="operator-workflow__stage" id="observe">
          <div className="operator-workflow__stage-inner">
            <div className="operator-workflow__stage-index"><span>03</span><small>of 05</small></div>
            <div className="operator-workflow__stage-copy">
              <h2>Observe</h2>
              <p>Read live resource probes, processes, logs, and service state without installing an agent.</p>
            </div>

            <div className="operator-workflow__stage-shot"><ProductShot name="logs" /></div>
          </div>
        </section>

        <section className="operator-workflow__stage operator-workflow__stage--operate" id="operate">
          <div className="operator-workflow__stage-inner">
            <div className="operator-workflow__stage-index"><span>04</span><small>of 05</small></div>
            <div className="operator-workflow__stage-copy">
              <h2>Operate</h2>
              <p>Move between terminals, files, scripts, deployments, keys, and backups without changing tools.</p>
            </div>
            <ul className="operator-workflow__operate-facts" aria-label="Oars terminal capabilities">
              <li>Interactive PTY shells</li>
              <li>Concurrent exec channels</li>
              <li>Approval-gated assisted commands</li>
            </ul>

            <div className="operator-workflow__focused-product">
              <ScreenshotGallery />
            </div>
          </div>
        </section>

        <section className="operator-workflow__stage operator-workflow__stage--recover" id="recover">
          <div className="operator-workflow__stage-inner">
            <div className="operator-workflow__stage-index"><span>05</span><small>of 05</small></div>
            <div className="operator-workflow__stage-copy">
              <h2>Recover</h2>
              <p>Use local history, audit trails, encrypted vault export, and backup runs when something goes wrong.</p>
              <a className="operator-workflow__inline-link" href={githubUrl}>
                Explore the source
                <ArrowUpRightIcon className="operator-workflow__icon" size={16} aria-hidden="true" />
              </a>
            </div>

            <div className="operator-workflow__stage-shot"><ProductShot name="history" /></div>
          </div>
        </section>
      </main>

      <footer className="operator-workflow__footer">
        <div className="operator-workflow__footer-top">
          <a href="#top">Oars</a>
          <p>Local-first Linux server management.</p>
          <div><a href={githubUrl}><GithubIcon className="operator-workflow__icon" size={15} aria-hidden="true" />GitHub</a><a href={`${githubUrl}/blob/main/LICENSE`}>MIT License</a></div>
        </div>
        <div className="operator-workflow__masthead" aria-hidden="true">OARS</div>
      </footer>
    </div>
  );
}
