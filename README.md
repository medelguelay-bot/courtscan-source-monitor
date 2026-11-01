# CourtScan public source monitor

Publish ONLY this directory as `medelguelay-bot/courtscan-source-monitor` (main branch).
It contains public data, attributed source URLs, monitoring code/tests and text snapshots.
No application server, local drafts, account data, credentials or deployment token belong here.
The daily workflow is installed and active at 06:17 UTC. Its first hosted run completed on 2026-11-01: 221 successful baseline checks and 71 visible errors, with results committed before CI reported failure. See the latest data/source-status.json for current counts.

Run `python -m pip install -r requirements.txt`, then `python -m unittest discover -s tests -v`, then `python monitor.py`.
Python 3.12 and the pinned pypdf version are the workflow target. The monitor has no secrets.
The built-in GitHub job token commits only `data/` and `snapshots/`; no external token is needed.

## Source scope and semantics

`allowlist.json` is an explicit frozen list derived only from accepted record sourceUrl/sourceLinks.
292 original HTTPS URLs are allowlisted. Five distinct publisher/archive URLs are skipped with reasons.
Two records have no monitored original URL; see `data/source-status.json`. No URL discovery, docket crawling or arbitrary URL input exists.
The list includes non-court original legislation and professional guidance already in the dataset; these are not relabeled court orders.
Redirects are HTTPS only and limited to the explicitly listed hosts; each hop rejects non-public IP addresses, and TLS connections pin the checked address.
Four workers maximum, four requests per source maximum, 8 MiB body, 2 MiB extracted text, 500 PDF pages, 40 seconds per source process, 600-second run scheduling budget.
Unstarted budget-limited sources are ERROR, never unchanged. No proxy environment is used.

First actual observation is BASELINED. Text is NFKC/whitespace normalized, hashed with SHA256, stored in immutable content-addressed snapshots and compared with a unified text diff.
PDF bytes/metadata are not the change oracle. No OCR; scanned PDFs, extraction failures, unsupported formats and challenges remain ERROR.
Whole visible HTML can include navigation changes and conservatively trigger review. Extraction is not a legal-change classifier.
The initial snapshot is the accepted public dataset, not a fabricated court-text baseline. All 292 checks start PENDING.

Changed text sets reviewRequired, REVIEW_REQUIRED, and generationEligible=false without rewriting legal summaries/status or historical primaryReview.
Repeated unchanged checks never clear a review flag. A curator must independently review the source and all related record checks before deliberately restoring eligibility; automation does not restore it.
Errors retain the last successful hash. Current error and stale checks block new frontend filing language. The frontend uses a 48-hour freshness bound and requires matching publication IDs for dataset, status and changelog.
Each source gets a visible status. Counts distinguish successful checks, errors, pending and skipped URLs; none imply nationwide coverage.

JSON files are individually atomically replaced; source manifests are published last. Consumers reject mixed run IDs. Git publishes the complete set in one commit.
Changelog events are append-only: URL, time, previous/new text hashes, snapshot and diff. Never prune or rewrite existing events to make a run appear clean.
Source errors are committed and then fail CI, retaining diagnostics. An abrupt process/runner failure can leave the previous publication; freshness eventually blocks generation. Workflow errors need operator attention.

## Attribution and rights

Adapted SafeLegalAI Legal AI Regulation Documents and US Court AI Orders, CC BY 4.0:
https://github.com/SafeLegalAI/legal-ai-regulation-documents
https://github.com/SafeLegalAI/us-court-ai-orders
https://creativecommons.org/licenses/by/4.0/
CourtScan changes: U.S. selection, schema normalization, primary-source summaries, explicit uncertainty and monitoring annotations.
Original documents retain their applicable rights and terms. Attribution implies no endorsement. Extracted source text is public-source material, not client or account data.

## Original activation handoff (completed 2026-11-01)

After root creates and publishes the repository, verify raw JSON responses and enable the daily workflow. Check its first actual run and failures.
Then merge the three entries in the frontend handoff `rewrites.pending.json` into `vercel.json`. Never activate rewrites before repository availability.
Live publication: https://courtscan.io. First hosted run: https://github.com/medelguelay-bot/courtscan-source-monitor/actions/runs/41323216264. Source retrieval errors remain explicit; no legal currency or completeness certification is claimed.

## Text publication boundary

All allowlisted sources are checked. Public text snapshots and unified diffs are limited to the explicit publicTextUrls federal court/government list and permitted final hosts. Other sources publish normalized-text hashes and change status only: their document text is not persisted or redistributed. A hash change still triggers reviewRequired and blocks affected filing language. Null diff means no public textual diff, not no change.
