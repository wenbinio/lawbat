# BLI Legal Tech Hackathon 2 — submission notes

Portal: [DoraHacks — BLI Legal Tech Hackathon 2](https://dorahacks.io/hackathon/1904).

Event page: [bli.tools/hackathon](https://bli.tools/hackathon/).

Organisers asked for a public code repository, architecture documentation, and a video demo, submitted on the DoraHacks page. This repository is the code. [ARCHITECTURE.md](../ARCHITECTURE.md) is the architecture note. The script below is the video.

Dates published as of 30 October 2026 do not all match. DoraHacks lists the deadline as **2026-11-01 01:01**. BLI posts also say **31 October 2026**. The BLI hackathon page says judging runs **5 November–5 December 2026**, with awards on **12 December 2026**. Submit before the earlier deadline. The listed prize pool can change. Sponsors named on the BLI site include RYO Digital and Chainlink Labs.

## Project title

Lawbat

## One-line tagline

Local-first redaction and re-identification risk checks for legal documents.

## Short description

Lawbat is local review software for an exported legal data room. A small firm often receives a folder of PDFs, emails, and office files and then has to search it, list it, and strip identifiers before anything is shared. Hosted review tools assume IT staff and an upload of privileged material. Lawbat does the work on the lawyer's own machine. It indexes the folder, leaves the originals read-only, and builds a schedule of documents. Redaction is deterministic: the engine proposes emails, numbers, IDs, and known party names, and the lawyer confirms what is removed. A document workspace makes release a second step after inspection. A separate screen estimates how unique a passage remains. There is no model call and no network. Removing identifiers is not a finding that a document is safe to send. The code is AGPL-3.0.

## Long description

Lawyers still receive a data room as a folder. A share purchase, a financing, or a regulatory response arrives as PDFs, emails, spreadsheets, and slide decks. The working questions are ordinary: what is in this folder, which document is which, and what has to be removed before a draft is sent on. The tools that answer those questions well are built for large firms. They expect an IT department and a willingness to upload privileged material. A small firm often has neither. The fallback is desktop search, a hand-built schedule, and find-and-replace. That misses scanned pages and leaves identifiers in the copy that is actually sent.

Lawbat is a local review desk for that folder. It runs on the lawyer's own computer. The exported originals stay read-only. The index, the schedule, and any redacted copy live in the application's own data directory. Nothing in the tool calls a model or opens a network connection. The pages are self-contained, so the same screen works in a browser and in a native window with no address bar.

Search is full-text over PDF, Word, Excel, PowerPoint, plain text, and email. A document index builds a schedule, grouped by folder, and exports a spreadsheet-friendly CSV. Scanned pages are labelled as needing OCR.

Redaction is a separate step. A Rust engine finds emails, phone numbers, ID-shaped strings, payment numbers, web addresses, and names the lawyer already knows. The reviewer walks Document, Detect, Review, Export, and Report. Sensitive passages are acknowledged inside Review, and Export stays locked until that work is done. On a digital PDF the engine removes the underlying text. A folder of files can be reviewed as a batch. The document workspace adds an inspect-then-release gate: preparation does not itself publish the file, and a reported removal failure cannot be overridden by clicking through.

A re-identification screen estimates how unique a description still is. The estimate is an optimistic lower bound. It raises concern. It never clears a document.

That is the RegTech point. Confidentiality is a duty about custody and judgment. A tool that keeps the file on the machine and refuses to call the result safe to send matches how that duty works. The review happens before anyone decides to place the same material in a cloud tool or an on-chain system.

What comes next is a signed Windows installer a non-technical user can double-click, and operating-system custody for the audit key. The lawyer stays in the loop.

## Tracks and categories

DoraHacks tags this hackathon with Blockchain, Crypto, Legal, Finance, Compliance, AI, RWA, RegTech, platform technology, Bitcoin, and Ethereum.

The organisers have described a Caffeine AI track (automated workflows and practical enterprise tools) and a Chainlink track (decentralised applications, smart contracts, and real-world-asset data). Later posts also emphasise payment rails.

File Lawbat as **Legal**, **RegTech**, and **Compliance**. On the Caffeine track it matches automated workflows and practical enterprise tools: search, a document schedule, and a confirmed redaction pass. It does not call a language model, and it should not be described as an AI agent. It does not target the Chainlink track, payment rails, stablecoins, or RWA oracles. If the form forces a single track, choose the enterprise-workflow side of the Caffeine track.

## Demo video script

About two and a half minutes. Record the screen and the voice together. Use a clone that has already run the [README](../README.md) demo setup (`cargo build -p redact-cli -p viewgen --release`, then `./run.sh --demo`). The sample matter is fictional. Say that once, on camera.

**Shot 1 — start (about 15 seconds).**  
Terminal in the repo root. Run `./run.sh --demo`.  
Narration: "Lawbat reviews a legal data room on this machine. The folder I am about to open is fictional sample data, not a client file. Nothing is uploaded."

**Shot 2 — Home (about 20 seconds).**  
Browser opens at `http://127.0.0.1:8077/`. Pause on the line that data stays on this machine.  
Narration: "This is the home screen. If you see a preview banner, the worklist generator was not built and this is a labelled sample. Next is the folder itself."

**Shot 3 — search (about 25 seconds).**  
Go to `http://127.0.0.1:8077/app`. Search `Harbour Lane`. Click one hit so the filename is visible.  
Narration: "This is an exported room: a letter, an email, and a directors list. Search is full-text, on a local index. The originals are not modified."

**Shot 4 — schedule (about 15 seconds).**  
Click **Tools**. Under **Document index**, click **Build index**.  
Narration: "The schedule is a read-only list of that same folder, grouped by folder."

**Shot 5 — redaction (about 50 seconds).**  
Open `http://127.0.0.1:8077/redaction`. Click **Try it with a sample document**. Click **Continue to detection settings**, then **Scan this document**. Under **Please review**, click **Keep all**. Tick every sensitive-passage box on this same Review stage. The hint is to tick each box before you can continue. Then **Continue to Export** and **Save redacted copy**. Show the report stage. Do not claim the document is clear.  
Narration: "Redaction does not guess with a model. The engine marks identifiers, and I decide what is removed. On a text PDF it deletes the text. The screen still will not tell me this is safe to send."

**Shot 6 — workspace and re-identification (about 30 seconds).**  
Open `http://127.0.0.1:8077/workspace` long enough to show the header "Inspect first. Release deliberately." Then open `http://127.0.0.1:8077/reid-risk`, paste `demo/sample-room/02-corporate/directors.md`, and click **Estimate k**. Pause on the banner that k can understate risk.  
Narration: "Release is a second step, after inspection. And stripping an email address does not make a person anonymous. This estimate only raises concern."

**Shot 7 — close (about 10 seconds).**  
Narration: "That is Lawbat. Local search, a schedule, and a redaction the lawyer confirms. The code is AGPL, and the file never had to leave the machine."
