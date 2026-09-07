import { lazy, Suspense } from "react";
import type { ResourceSample } from "../resource-history";
const Chart = lazy(() => import("./ResourceChart"));
export function ResourceChart(props: { samples: ResourceSample[]; compact?: boolean }) {
  return <Suspense fallback={<div className="resource-chart-empty" role="status">Loading chart…</div>}><Chart {...props} /></Suspense>;
}
