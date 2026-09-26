# beaksec — blog

Jekyll + [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy) 7.6,
built and deployed by GitHub Actions.

## Local preview

```bash
bundle install                             # first time only
bundle exec jekyll serve --livereload      # http://127.0.0.1:4000
```

Add `--drafts` to also render files in `_drafts/`.
Changes to `_config.yml` require restarting the server.

## Publishing (one time)

`_config.yml` is already configured. Create the `beaksec` GitHub account, then:

```bash
gh auth login                        # GitHub.com > HTTPS > web browser
gh auth switch --user beaksec

git init -b main
git add -A
git commit -m "Initial commit"
gh repo create beaksec.github.io --public --source=. --remote=origin --push
```

Then on GitHub: **Settings > Pages > Source: GitHub Actions**.
The site goes live at https://beaksec.github.io after 1-2 minutes.

> The repository must be named exactly `beaksec.github.io` to get the clean URL.

## Writing a post

Create `_posts/YYYY-MM-DD-slug.md`:

```markdown
---
title: "Pre-auth RCE in Acme Router 1.2.3"
date: 2026-01-15 10:00:00 +0100
categories: [Research, PoC]
tags: [poc, exploit]
description: "Used for the meta description and link previews."
pin: false
---

Post body.
```

Then `git add -A && git commit -m "new post" && git push` — the build runs on its own.

**The filename determines the URL**, so don't rename it after publishing.

Useful Chirpy syntax:

| | |
|---|---|
| Callout boxes | `{: .prompt-tip }` `.prompt-info` `.prompt-warning` `.prompt-danger` |
| Math | `math: true` in the front matter |
| Diagrams | `mermaid: true` in the front matter |
| Images | put them in `assets/img/posts/<slug>/` |

## Permalinks

Set explicitly in `_config.yml`, independent of the theme:

```yaml
permalink: /posts/:title/      # posts
permalink: /tags/:name/        # tags
permalink: /categories/:name/  # categories
```

If you switch themes later, copy these values into the new `_config.yml` and no
link breaks. Don't change them after publishing.

## Site images

Derived from the YouTube channel avatar (559x559 original: on a
`googleusercontent.com` URL, a trailing `=s0` always returns full resolution).

| File | Use |
|---|---|
| `assets/img/avatar.jpg` | 512x512, sidebar |
| `assets/img/social-preview.jpg` | 1200x630, social link preview |
| `assets/img/favicons/*` | cropped to the crow's head so they stay legible at 16px |

The favicons override the theme's: Chirpy looks for them in
`assets/img/favicons/`, so the filenames must stay as they are.

## Changes from chirpy-starter

- `_config.yml`: title, tagline, URL, social links, avatar, `social_preview_image`,
  `timezone`, `theme_mode: dark`
- `pwa.enabled: false` — no service worker
- `twitter:` key commented out (present but empty, `jekyll-seo-tag` emits a
  useless `<meta name="twitter:site" content="@">`)
- removed the `assets/lib` submodule: assets are served from the jsDelivr CDN

## Optional

- **Comments**: `comments:` section in `_config.yml` (giscus / utterances / disqus)
- **Analytics**: `analytics:` section (GoatCounter and Umami are the most privacy-friendly)
- **Custom domain**: a `CNAME` file with the domain + DNS pointing at GitHub Pages
- **Search Console**: verification code in `webmaster_verifications.google`
- **Zero external requests**: `assets.self_host.enabled: true` plus restoring the
  `chirpy-static-assets` submodule, to drop jsDelivr and Google Fonts
