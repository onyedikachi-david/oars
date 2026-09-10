import { useState } from "react";
import benchmark from "../data/memory-benchmark.json";
import "./memory-benchmark.css";

const axisMaximum = 500;
const percentage = (value: number) => `${value / axisMaximum * 100}%`;

export function MemoryBenchmark() {
  const [replay, setReplay] = useState(0);

  return <section className="section memory-section" id="memory" aria-labelledby="memory-title">
    <div className="feature-copy memory-copy">
      <span className="section-label">A little space for a lot of servers</span>
      <h2 id="memory-title">15 connections.<br />About 300 MiB.</h2>
      <p>From an empty workspace to live monitoring, here’s how Oars’s memory use changed in our MacBook Air test.</p>
      <a className="inline-link" href="/benchmarks/oars-memory-v0.4.0.png" download>Download the chart <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 16v4h14v-4" /></svg></a>
    </div>
    <figure className="memory-chart" aria-label="Oars memory benchmark">
      <div className="memory-chart__heading">
        <div><h3>Memory in use</h3><p>Whole app, including WebKit helpers</p></div>
        <span className="memory-chart__version">v{benchmark.version}</span>
      </div>
      <ol className="memory-chart__rows" aria-label="Measured memory use">
        {benchmark.rows.map(row => <li key={row.id} className={`memory-chart__row${row.id === "idle15" ? " memory-chart__row--highlight" : ""}`}>
          <div className="memory-chart__label"><strong>{row.label}</strong><span>{row.detail}</span></div>
          <div className="memory-chart__value">{row.median.toFixed(1)} <small>MiB</small><span className="memory-chart__sr-only"> median, observed range {row.min.toFixed(1)} to {row.max.toFixed(1)} MiB.</span></div>
          <div className="memory-chart__track" aria-hidden="true">
            <div key={replay} className={`memory-chart__marks${replay ? " memory-chart__marks--replay" : ""}`}>
              <div className="memory-chart__fill" style={{ width: percentage(row.median) }} />
              <span className="memory-chart__range" style={{ insetInlineStart: percentage(row.min), width: percentage(row.max - row.min) }} />
            </div>
          </div>
        </li>)}
      </ol>
      <div className="memory-chart__axis" aria-hidden="true">
        {[0, 100, 200, 300, 400, 500].map(tick => <span key={tick} style={{ insetInlineStart: percentage(tick) }}>{tick}</span>)}
      </div>
      <figcaption className="memory-chart__caption">
        <p>Median RAM · markers show the observed range</p>
        <div className="memory-chart__actions">
          <details><summary>Test details</summary><p>{benchmark.hardware} MacBook Air · {benchmark.ramGiB} GiB RAM · {benchmark.os}<br />{benchmark.build} · 9 Sep 2026<br />{benchmark.warmupSeconds} s warm-up, then 12 samples over {benchmark.sampleWindowSeconds} s.</p></details>
          <button className="memory-chart__replay" onClick={() => setReplay(value => value + 1)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M20 7v5h-5M20 12a8 8 0 1 0-2.3 5.7" /></svg>
            Replay
          </button>
        </div>
      </figcaption>
    </figure>
  </section>;
}
