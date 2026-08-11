export function localParent(path: string): string {
  const separator = path.includes("\\") && !path.includes("/") ? "\\" : "/";
  const normalized = path.replace(/[\\/]+$/, "");
  const index = normalized.lastIndexOf(separator);
  if (index < 0) return path;
  if (index === 0) return separator;
  if (separator === "\\" && index === 2 && normalized[1] === ":") return normalized.slice(0, 3);
  return normalized.slice(0, index);
}

export function localJoin(parent: string, leaf: string): string {
  const separator = parent.includes("\\") && !parent.includes("/") ? "\\" : "/";
  return `${parent.replace(/[\\/]+$/, "")}${separator}${leaf.replace(/[\\/]/g, "_")}`;
}
