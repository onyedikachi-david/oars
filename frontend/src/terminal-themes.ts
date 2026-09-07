import type { ITheme } from "xterm";

export const OARS_TERMINAL_THEME = {
  background: "#0f1318",
  foreground: "#dbe2ea",
  cursor: "#7aa8ff",
  cursorAccent: "#0f1318",
  selectionBackground: "rgba(122, 168, 255, 0.28)",
  black: "#1c2128",
  red: "#ff5f56",
  green: "#98c379",
  yellow: "#e5c07b",
  blue: "#61afef",
  magenta: "#c678dd",
  cyan: "#56b6c2",
  white: "#abb2bf",
  brightBlack: "#5c6370",
  brightRed: "#ff6c66",
  brightGreen: "#b5e890",
  brightYellow: "#ffd866",
  brightBlue: "#82b4ff",
  brightMagenta: "#d98ce0",
  brightCyan: "#6fd3de",
  brightWhite: "#e8ecf2",
};


// Palette sources: ethanschoonover.com/solarized and atom/one-dark-syntax/styles/colors.less.
export const ONE_DARK: ITheme = { ...OARS_TERMINAL_THEME, background: "#282c34", foreground: "#abb2bf", cursor: "#528bff", cursorAccent: "#282c34", black: "#282c34", red: "#e06c75", green: "#98c379", yellow: "#e5c07b", blue: "#61afef", magenta: "#c678dd", cyan: "#56b6c2", white: "#abb2bf" };
export function solarized(light: boolean): ITheme {
  return { background: light ? "#fdf6e3" : "#002b36", foreground: light ? "#657b83" : "#839496", cursor: light ? "#586e75" : "#93a1a1", cursorAccent: light ? "#fdf6e3" : "#002b36", selectionBackground: light ? "#eee8d5" : "#073642", black: "#073642", red: "#dc322f", green: "#859900", yellow: "#b58900", blue: "#268bd2", magenta: "#d33682", cyan: "#2aa198", white: "#eee8d5", brightBlack: "#002b36", brightRed: "#cb4b16", brightGreen: "#586e75", brightYellow: "#657b83", brightBlue: "#839496", brightMagenta: "#6c71c4", brightCyan: "#93a1a1", brightWhite: "#fdf6e3" };
}
export const PLAIN_ANSI: ITheme = { background: "#000000", foreground: "#ffffff", cursor: "#ffffff", cursorAccent: "#000000", selectionBackground: "#555555", black: "#000000", red: "#800000", green: "#008000", yellow: "#808000", blue: "#000080", magenta: "#800080", cyan: "#008080", white: "#c0c0c0", brightBlack: "#808080", brightRed: "#ff0000", brightGreen: "#00ff00", brightYellow: "#ffff00", brightBlue: "#0000ff", brightMagenta: "#ff00ff", brightCyan: "#00ffff", brightWhite: "#ffffff" };
