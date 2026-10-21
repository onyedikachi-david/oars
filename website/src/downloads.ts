export const githubUrl = "https://github.com/onyedikachi-david/oars";
export const sponsorUrl = "https://github.com/sponsors/onyedikachi-david";
export const downloadsApiUrl = "/api/downloads";
export const githubReleasesApiUrl = "https://api.github.com/repos/onyedikachi-david/oars/releases?per_page=100";

// CI publishes these stable aliases alongside each versioned release asset.
export const downloads = {
  macos: `${githubUrl}/releases/latest/download/oars-macos.zip`,
  linux: `${githubUrl}/releases/latest/download/oars-linux-x86_64.tar.gz`,
};

export interface DownloadStats {
  total: number;
  macos: number;
  linux: number;
}

const ARCHIVE_PATTERN = /\.(?:zip|tar\.gz)$/i;
const STORAGE_KEY = "oars:download-stats:v1";
const CACHE_TTL_MS = 5 * 60 * 1000;
const numberFormatter = new Intl.NumberFormat("en-US");

interface GithubReleaseAsset {
  name?: string;
  download_count?: number;
}

interface GithubRelease {
  draft?: boolean;
  assets?: GithubReleaseAsset[];
}

export function summarizeReleases(releases: unknown): DownloadStats {
  let total = 0;
  let macos = 0;
  let linux = 0;

  if (!Array.isArray(releases)) {
    return { total, macos, linux };
  }

  for (const release of releases as GithubRelease[]) {
    if (!release || release.draft || !Array.isArray(release.assets)) continue;
    for (const asset of release.assets) {
      const name = typeof asset?.name === "string" ? asset.name : "";
      const count = Number(asset?.download_count) || 0;
      if (!ARCHIVE_PATTERN.test(name) || count <= 0) continue;
      total += count;
      if (/macos/i.test(name)) {
        macos += count;
      } else if (/linux/i.test(name)) {
        linux += count;
      }
    }
  }

  return { total, macos, linux };
}

export function formatDownloadCount(count: number): string {
  const safeCount = Math.max(0, Math.floor(count));
  return `${numberFormatter.format(safeCount)} ${safeCount === 1 ? "download" : "downloads"}`;
}

function readCachedStats(): DownloadStats | null {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { timestamp?: number; stats?: DownloadStats };
    if (
      typeof parsed?.timestamp !== "number" ||
      Date.now() - parsed.timestamp > CACHE_TTL_MS ||
      typeof parsed?.stats?.total !== "number"
    ) {
      return null;
    }
    return parsed.stats;
  } catch {
    return null;
  }
}

function writeCachedStats(stats: DownloadStats): void {
  try {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ timestamp: Date.now(), stats }),
    );
  } catch {
    // Ignore storage quota or privacy-mode errors.
  }
}

export function recordLocalDownload(platform: "macos" | "linux"): void {
  const cached = readCachedStats();
  if (!cached) return;
  writeCachedStats({
    total: cached.total + 1,
    macos: platform === "macos" ? cached.macos + 1 : cached.macos,
    linux: platform === "linux" ? cached.linux + 1 : cached.linux,
  });
}

export async function fetchDownloadStats(signal?: AbortSignal): Promise<DownloadStats | null> {
  const cached = readCachedStats();
  if (cached) return cached;

  try {
    const response = await fetch(downloadsApiUrl, {
      headers: { Accept: "application/json" },
      signal,
    });
    if (response.ok) {
      const data = (await response.json()) as Partial<DownloadStats>;
      if (typeof data?.total === "number" && data.total >= 0) {
        const stats: DownloadStats = {
          total: data.total,
          macos: typeof data.macos === "number" ? data.macos : 0,
          linux: typeof data.linux === "number" ? data.linux : 0,
        };
        writeCachedStats(stats);
        return stats;
      }
    }
  } catch {
    if (signal?.aborted) return null;
  }

  try {
    const response = await fetch(githubReleasesApiUrl, {
      headers: { Accept: "application/vnd.github+json" },
      signal,
    });
    if (!response.ok) return null;
    const releases = await response.json();
    const stats = summarizeReleases(releases);
    writeCachedStats(stats);
    return stats;
  } catch {
    return null;
  }
}

