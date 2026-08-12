import React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const deploymentLabel = import.meta.env.VITE_DEPLOYMENT_LABEL || "local-build";

function App() {
  return React.createElement(
    "main",
    { className: "page" },
    React.createElement(
      "section",
      { className: "card", "aria-labelledby": "title" },
      React.createElement("span", { className: "eyebrow" }, "Oars deployment check"),
      React.createElement("div", { className: "status", "aria-hidden": "true" }, React.createElement("i"), "Live"),
      React.createElement("h1", { id: "title" }, "React reached this Contabo server."),
      React.createElement("p", { className: "lede" }, "The repository was installed, built, and served through the Oars Nginx deployment path."),
      React.createElement(
        "dl",
        { className: "facts" },
        React.createElement("div", null, React.createElement("dt", null, "Build label"), React.createElement("dd", { id: "build-label" }, deploymentLabel)),
        React.createElement("div", null, React.createElement("dt", null, "Renderer"), React.createElement("dd", null, `React ${React.version}`)),
        React.createElement("div", null, React.createElement("dt", null, "Health marker"), React.createElement("dd", { id: "health-marker" }, "oars-smoke-ok")),
      ),
      React.createElement("p", { className: "hint" }, "Change VITE_DEPLOYMENT_LABEL in Oars and deploy again to test the update path."),
    ),
  );
}

createRoot(document.getElementById("root")).render(React.createElement(App));
