import { StrictMode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";
import "../tokens.css";
import "./site-base.css";
import App from "./App";

const root = document.getElementById("root")!;
const app = <StrictMode><App /></StrictMode>;

if (root.hasChildNodes()) {
  hydrateRoot(root, app);
} else {
  createRoot(root).render(app);
}
