import { StrictMode } from "react";
import { renderToString } from "react-dom/server";
import App from "./App";

// This page has no asynchronous data. Render the same tree that the client hydrates.
export function render() {
  return renderToString(<StrictMode><App /></StrictMode>);
}
