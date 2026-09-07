import { useState } from "react";
import { ArrowUpRightIcon } from "./icons/arrow-up-right";

const screenshots = {
  files: { title: "Files", caption: "Local and remote files, side by side.", alt: "Oars file manager showing local folders alongside a remote Linux filesystem. Private file names are redacted." },
  logs: { title: "Logs", caption: "Find a source, inspect its output, and follow new lines.", alt: "Oars log viewer with a source list, search controls, and server log output. Connection details are redacted." },
  ai: { title: "AI assistance", caption: "Keep the conversation and reviewed commands together.", alt: "Oars AI workspace with a provider, reviewed Docker command, and conversation. Private identifiers and infrastructure details are redacted." },
  deploy: { title: "Deployments", caption: "Start with a repository. Review the plan before a deployment.", alt: "Oars deployment workspace ready to add its first application." },
  history: { title: "History", caption: "Return to recorded commands and their outcomes.", alt: "Oars command history with recorded times, exit codes, and replay controls. Private connection information is redacted." },
  desktop: { title: "Remote desktop", caption: "An XFCE desktop, connected through an SSH tunnel.", alt: "Oars displaying a connected XFCE remote desktop in its server workspace. Server addresses are redacted." },
  fullscreen: { title: "Full screen", caption: "Give the remote desktop room to work.", alt: "An XFCE desktop in Oars full-screen mode with connection and scaling controls." },
} as const;
export type ScreenshotName = keyof typeof screenshots;

export function ProductShot({ name, priority = false, caption = true }: { name: ScreenshotName; priority?: boolean; caption?: boolean }) {
  const shot = screenshots[name];
  return <figure className="product-shot">
    <a className="product-shot__image" href={`/screenshots/${name}-2560.webp`} target="_blank" rel="noopener noreferrer" aria-label={`Open ${shot.title.toLowerCase()} screenshot at full size`}>
      <img src={`/screenshots/${name}-1600.webp`} srcSet={`/screenshots/${name}-960.webp 960w, /screenshots/${name}-1600.webp 1600w, /screenshots/${name}-2560.webp 2560w`} sizes="(max-width: 820px) 92vw, 1200px" width="1600" height="1000" alt={shot.alt} loading={priority ? "eager" : "lazy"} decoding="async" fetchPriority={priority ? "high" : "auto"} />
    </a>
    {caption && <figcaption><span><strong>{shot.title}</strong>{shot.caption}</span><a href={`/screenshots/${name}-2560.webp`} target="_blank" rel="noopener noreferrer">Full size <ArrowUpRightIcon size={14} aria-hidden="true" /></a></figcaption>}
  </figure>;
}

export function ScreenshotGallery() {
  const [selected, setSelected] = useState<ScreenshotName>("files");
  return <div className="product-gallery">
    <div className="product-gallery__bar"><span>Inside Oars</span><div className="product-gallery__choices" role="group" aria-label="Choose a product screenshot">{(Object.keys(screenshots) as ScreenshotName[]).map(name => <button key={name} type="button" aria-pressed={selected === name} aria-controls="product-gallery-image" onClick={() => setSelected(name)}>{screenshots[name].title}</button>)}</div></div>
    <div id="product-gallery-image" className="product-gallery__stage"><ProductShot key={selected} name={selected} /></div>
    <p className="product-gallery__privacy">Captured in the desktop app. Private details have been redacted.</p>
  </div>;
}
