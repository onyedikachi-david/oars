# Oars website

The public site is served at https://getoars.app/. It uses Vite and React, with static HTML generated at build time and hydrated in the browser.

```sh
npm ci
npm run build
npm run preview
```

`npm run build` type-checks the site, builds the client, renders the same React page into `dist/index.html`, and runs the SEO checks. The temporary server bundle stays under ignored `node_modules/.cache/` and is removed afterward. No Node server is needed in production.

## Search and sharing

- `index.html`: title, description, canonical URL, Open Graph, X cards, and JSON-LD.
- `public/og/oars.png`: 2400 × 1260 lossless PNG social image (1200 × 630 composition rendered at 2× pixel density). The HTML artwork is in `scripts/social-preview.html`; render it with the public asset paths available at the server root. Export directly as PNG; converting a JPEG capture to PNG does not restore detail. The artwork is not shipped as a separate public page.
- `public/sitemap.xml`: only the canonical homepage. Section anchors are not separate pages. Add real page URLs if the site grows; do not invent modification dates.
- `public/robots.txt`: allows public crawling and points to the sitemap.
- `vercel.json`: redirects `/index.html` to the canonical homepage.
- `public/404.html`: noindex error page for static hosting, including Vercel. Keep unknown URLs as HTTP 404s; do not add a catch-all rewrite to the homepage.
- `scripts/seo.test.mjs`: verifies crawlable content, canonical consistency, social-image format/dimensions, structured data, local assets, and section links. CI runs these through the website build.

The software schema describes shipped macOS/Linux functionality. Roadmap ideas are not listed as current features. No reviews or aggregate ratings are invented; software rich-result eligibility is not guaranteed.

After deployment, verify the live response for `/`, `/og/oars.png`, `/robots.txt`, `/sitemap.xml`, and a missing URL. Submit `https://getoars.app/sitemap.xml` in Google Search Console using the site owner's account. Use Google's URL Inspection and Rich Results Test to check the deployed URL. Indexing and ranking remain search-engine decisions.

References: [Google JavaScript SEO](https://developers.google.com/search/docs/crawling-indexing/javascript/javascript-seo-basics), [Open Graph](https://ogp.me/), [React hydration](https://react.dev/reference/react-dom/client/hydrateRoot), [Vercel 404 pages](https://vercel.com/kb/guide/custom-404-page).
