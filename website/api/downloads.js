const RELEASES_URL = "https://api.github.com/repos/onyedikachi-david/oars/releases?per_page=100";
const ARCHIVE_PATTERN = /\.(?:zip|tar\.gz)$/i;
const MAX_PAGES = 5;

export function summarizeReleases(releases) {
  let total = 0;
  let macos = 0;
  let linux = 0;

  if (!Array.isArray(releases)) {
    return { total, macos, linux };
  }

  for (const release of releases) {
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

export async function fetchAllReleaseStats(fetchImpl = fetch, token = process.env.GITHUB_TOKEN) {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "oars-website",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const allReleases = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const response = await fetchImpl(`${RELEASES_URL}&page=${page}`, { headers });
    if (!response.ok) {
      throw new Error(`GitHub API responded with status ${response.status}`);
    }
    const releases = await response.json();
    if (!Array.isArray(releases)) {
      throw new Error("Invalid GitHub releases payload");
    }
    allReleases.push(...releases);
    if (releases.length < 100) break;
  }

  return summarizeReleases(allReleases);
}

export default async function handler(req, res) {
  if (req?.method && req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    res.setHeader("Allow", "GET, HEAD");
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ error: "Method not allowed" }));
    return;
  }

  try {
    const stats = await fetchAllReleaseStats();
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=300, s-maxage=3600, stale-while-revalidate=86400");
    res.end(req?.method === "HEAD" ? undefined : JSON.stringify(stats));
  } catch {
    res.statusCode = 502;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(req?.method === "HEAD" ? undefined : JSON.stringify({ error: "Unable to fetch download counts" }));
  }
}
