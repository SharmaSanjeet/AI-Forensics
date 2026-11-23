# AI-Assistant Query Artifacts — Reference Knowledge Base

Where AI assistants store what they store: a consolidated catalogue of on-disk
artifacts for Claude Code / Claude Desktop, OpenAI Codex, ChatGPT Desktop &
Atlas, ChatGPT Computer History, Cursor, Gemini CLI, Grok Build, Grok Bot,
GitHub Copilot, Windsurf and Continue.

Use it to plan acquisitions, explain coverage gaps, and target a full-disk
triage. Every path is a default per-platform location; exact names vary by
app version.

> **Scope note.** The *Evidence status* column reflects the consolidated
> research (what is recoverable and how it was handled). In the current
> AI-Forensics build, parsers ship for **Claude Code, OpenAI Codex, Cursor,
> Gemini CLI and GitHub Copilot**; rows for other applications are reference
> material for future parsers. Credential stores are inventoried or excluded,
> never copied.

*Compiled 2026-11-20 from public DFIR research. The editable master is
[`AI_Query_Artifacts_Consolidated.xlsx`](AI_Query_Artifacts_Consolidated.xlsx);
this page is generated from it by `tools/build_reference_doc.py`.*


## Artifact catalogue

### Claude Code / Desktop

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Claude Code CLI | ~/.claude/history.jsonl | Prompt history | Parsed | Fast view of intent, suspicious questions, credential pasting |
| Claude Code CLI | ~/.claude/projects/<project>/<session>.jsonl | Full session transcripts | Parsed | Prompts, replies, tool use, attachments, file snapshots, model/token data, sidechains |
| Claude Code CLI | ~/.claude.json and .claude.json.backup* | Per-project state | Parsed | Last session, start time, cost, trust dialog, allowed tools, MCP (env redacted), Remote Control flag, account IDs; backups reveal removed workspaces |
| Claude Code CLI | settings.json, .mcp.json | Config | Parsed | Model/permission posture, allow/ask/deny rules, hooks, status-line command, MCP definitions (secrets excluded) |
| Claude Code CLI | CLAUDE.md, MEMORY.md, skills/, plugins/, plans/, tasks/, todos/ | Instruction, memory and extension context | Hashed inventory | Path, size, mtime, bounded SHA-256 |
| Claude Code CLI | file-history/, backups/.claude.json.backup* | File revisions, state backups | Hashed inventory | Physical file revisions; backups link to current ~/.claude.json |
| Claude Code CLI | .credentials.json | Credential store | Excluded-content inventory | Path, size, mtime only; never opened or hashed |
| Claude Desktop | ~/Library/Application Support/Claude/claude-code-sessions/ (macOS); %APPDATA%\Claude\claude-code-sessions\ (Windows) | local_*.json session metadata | Parsed (metadata + linked transcripts) | Proves Desktop Code usage; links to .claude/projects transcripts |
| Claude Desktop / Cowork | .../Claude/local-agent-mode-sessions/ (local_*.json, isolated .claude/projects/**/*.jsonl, audit*.jsonl, .audit-key) | Cowork / legacy sessions | Parsed (recursive transcripts, audit rows) | Isolated Cowork transcripts not in ~/.claude/projects |
| Claude Desktop | claude-code-sessions/<account>/<org>/deleted_<session-uuid> | Deletion tombstone | Parsed | 13-byte file holding epoch-ms deletion time; proves a conversation existed and when removed (RecordType session_deleted) |
| Claude Desktop | <app-support>/pending-uploads/ | Staged uploads (<uuid>-<epoch_ms>_<name>) | Inventory-only | Shows files sent to assistant after chat is gone; content never read (RecordType pending_upload) |
| Claude Desktop | <app-support>/plan-usage-history.json | App-usage samples (~5 min) | Parsed (derived) | Contiguous 'app in use' windows; derived from sample spacing, not true session boundaries |
| Claude Desktop | scheduled-tasks.json, git-worktrees.json | Automation and workspaces | Parsed | Unattended agent runs (persistence surface); working directories with last-seen times |
| Claude Desktop | bridge-state.json | Remote Control state | Parsed | Local session linked to claude.ai session; consent flag |
| Claude Desktop | claude_desktop_config.json, config.json | Desktop config | Parsed | Trusted folders, remote folder grants, Cowork security prefs, MCP servers (env redacted) |

### OpenAI Codex

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Codex | ~/.codex/ (or $CODEX_HOME); %USERPROFILE%\.codex\ | Root | - | Thread transcripts live here, not in the Electron profile |
| Codex | history.jsonl | Prompt log | Parsed | session_id, ts, text |
| Codex | sessions/YYYY/MM/DD/rollout-*.jsonl; archived_sessions/ | Rollout transcripts | Parsed | Messages, tool calls/results, reasoning, media references with line/offset pointers |
| Codex | session_index.jsonl | Thread titles | Parsed | Metadata |
| Codex | state*.sqlite (+WAL/SHM) | Thread/state DB | Parsed | Thread, spawn-edge, dynamic-tool metadata, remote_control_enrollments, projects/project_roots |
| Codex | thread_history*.sqlite | Desktop SQL projection | Parsed (fallback only) | Used only when a rollout is missing/unreadable/partial |
| Codex | config.toml, AGENTS.md, instructions.md, skills/, plugins/ | Config and instructions | Parsed / hashed inventory | Project trust, MCP/plugin settings; auth.json never opened or hashed |
| Codex | rules/*.rules (e.g. default.rules) | Exec-policy allow-list | Parsed | Command prefixes that run without approval (RecordType exec_policy_rule) |
| Codex | shell_snapshots/<thread>.<ns>.sh | Exported shell environment | Parsed (names only) | World-readable; variable names and credential-looking ones flagged, values never read |
| Codex | sqlite/codex-dev.db | local_thread_catalog, automations | Parsed | Surface, missing-rollout flag, scheduled runs |
| Codex | logs*.sqlite | Tracing log | Parsed | UserInput bodies carry prompt text independent of rollouts |
| Codex | memories*.sqlite, memories/{MEMORY,raw_memories,memory_summary}.md, memories/extensions/ad_hoc/ | Model memory | Parsed | Persistent model-written memory of the user (thread_memory, agent_memory) |
| Codex | memories/rollout_summaries/*.md | Per-thread summaries | Parsed | Outlive the rollout; marked [rollout deleted] when transcript gone |
| Codex | hooks.json | Lifecycle hooks | Parsed | Commands run on lifecycle events (execution persistence) |
| Codex | .codex-global-state.json | Remote Control / SSH state | Parsed | SSH hosts with identity key path, Remote Control grants, phone pairing, local project roots |
| Codex | ambient-suggestions/<hash>/ambient-suggestions.json | Ambient suggestions | Parsed | Watched project roots, generated follow-up prompts, generation time |
| Codex | goals*.sqlite, queue*.sqlite, dictation-history/, transcription-history.jsonl | Goals, queued prompts, voice input | Parsed when populated | Standing goals, queued prompts, dictation |
| Codex | VS Code-family agentSessions.model.cache | Embedded provider cache | Parsed | Codex evidence when rollouts are sparse |

### ChatGPT Desktop / Atlas

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| ChatGPT | macOS: ~/Library/Application Support/com.openai.chat/; Atlas: .../OpenAI/Atlas/; merged app: .../Codex/ | App data roots | - | Windows: %AppData%\Roaming\OpenAI\ChatGPT\ or MS Store LocalCache path; Linux: ~/.config/com.openai.chat/ |
| ChatGPT | Local Storage/leveldb/*.ldb | LevelDB | Parsed | Conversation titles and timestamps |
| ChatGPT | SQLite stores | Message DB | Parsed when present | Full user/assistant bodies when the app version writes them locally |
| ChatGPT | conversations-v2-*, conversations-v3-*/*.data | Conversation bundles | Inventory-only | UUID, generation, project/store context, size, path; bodies not decoded |
| ChatGPT (merged Codex app) | ~/Library/Application Support/Codex (Chromium profile) | History visits, Local Storage metadata, artifact-sessions | Parsed / inventory | Login Data and Cookies not read; thread bodies remain under ~/.codex |
| ChatGPT (merged Codex app) | sentry/scope_v3.json, sentry/session.json | app_identity, app_breadcrumb | Parsed | User/account ID, auth method, build, OS; up to 200 breadcrumbs (HTTP calls, UI clicks, console errors) |
| ChatGPT (merged Codex app) | Default/ and codex-browser-app/ Login Data, Cookies, Web Data | Credential stores | Inventory by name/size | Never read; populated codex-browser-app means the agent held web sessions |
| ChatGPT | com.openai.chat/app_pairing_extensions/ | Work-with-Apps pairings | Parsed | Paired app, bundle ID, workspace, capabilities (setContent/replaceSelection = can write into editor) |

### ChatGPT Computer History (Skysight)

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Computer History | ~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Caches/ComputerUse/Skysight/segments/<bucket>/events.jsonl | Raw event stream | Parsed (own 54-column tab) | Focus, clicks, keystrokes, selections, drags, window/URL context; ~48h advertised retention, stopped recorder can leave segments longer |
| Computer History | segments/<bucket>/metadata.json | Segment metadata | Parsed | startedAt, endedAt, eventCount, suppressedEventCount; integrity anchor |
| Computer History | ~/.codex/memories/extensions/skysight/resources/*.md | Activity summaries (10min/6h) | Parsed | Model-generated; outlive raw purge |
| Computer History | ~/.codex/memories/ (incl. .git) | Consolidated memory + git repo | Parsed | Not cleared with Computer History; UI-cleared summaries recoverable from git |
| Computer History | ~/.codex/config.toml [plugins."computer-history@openai-bundled"] | Feature state | Parsed | Whether feature enabled |
| Computer History | CUAService/.../ComputerUseAppApprovals.json | Computer Use agent approvals | Parsed | Not the recording scope; separate feature |
| Computer History | CUAService/.../Analytics.db | Analytics store | Parsed | Uploaded then cleared; expect empty except live capture; distinct_id identifies recorder install |
| Attribution | ~/Library/Preferences/com.openai.sky.CUAService.plist, com.openai.chat.plist, com.openai.chat.RemoteFeatureFlags.<uuid>.plist, com.openai.chat.StatsigService.plist | Identity/pseudonym plists | Parsed | Account UUID, email/user ID (Statsig, no tokens), device stableID |
| Attribution | ~/.codex/auth.json, ~/.codex/installation_id | Sign-in identity / install ID | auth.json never opened | auth.json holds live bearer/refresh tokens; installation_id identifies Codex install |

### Cursor

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Agent transcripts | ~/.cursor/projects/<slug>/agent-transcripts/<session-id>/<session-id>.jsonl ($CURSOR_AGENT_HOME) | Agent transcripts (.jsonl/.txt) | Parsed | Instructions, replies, tool-use text, sidechain flags, workspace attribution |
| SQLite chats | globalStorage/state.vscdb, workspaceStorage/*/state.vscdb, ~/.cursor/chats/**/store.db | Composer / global / workspace chats | Parsed (needs SQLite support) | Chats not in transcript files; tool/interpreter results retained |
| Search index | Cursor/User/globalStorage/conversation-search.db (+WAL/SHM) | Local FTS index | Parsed | Title, indexed body, conversation ID, scope, archive state, update time; may hold body after transcript deleted |
| Config | hooks.json, mcp.json, .mcp.json | Hooks and MCP | Parsed | Hook commands, MCP definitions (secrets excluded) |
| Context | plans/, AGENTS.md, .cursorrules, rules/, skills/, plugins/ | Plans and agent context | Hashed inventory | Path, size, mtime, SHA-256 |
| Context | ai-tracking/*.db | AI tracking DBs | Hashed inventory | Raw index provenance; schema not claimed |

### Gemini CLI

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Chats | ~/.gemini/tmp/<hash-or-slug>/chats/**/*.jsonl | Chat JSONL | Parsed | Current reconstructed state plus immutable source-event history; rewound/superseded messages recoverable |
| Shell | ~/.gemini/shell_history | Shell history | Parsed | Exact entries incl. multiline commands |
| Legacy | session-*.json, logs.json, checkpoints | Older layouts | Parsed | Older Gemini CLI sessions |
| Workspace | projects.json, tmp/<slug>/.project_root, history/<slug>/.project_root | Workspace registry (0.58+) | Parsed | Slug directories replace hash-named folders |
| Config | settings.json (+backups), policies/* | Settings and policy | Parsed / inventoried | Auth type, retention, Auto Memory, hooks, MCP, tool policy (secrets excluded) |
| Context | GEMINI.md, skills/**/{SKILL.md,json,yaml} | Instructions, skills | Hashed inventory | Path, size, mtime, SHA-256 |
| Trust | trustedFolders.json | Trusted folders | Parsed | Folders CLI may act in without prompting |
| Identity | google_accounts.json, installation_id, user_id | Account/install IDs | Parsed | Identifiers |
| Credentials | oauth_creds.json (and MCP/A2A token files) | Token stores | Inventory-only | Name and size; never read |

### Grok Build

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Session | ~/.grok/ ($GROK_HOME) sessions/<encoded-cwd>/prompt_history.jsonl | Prompt history | Parsed | Timestamp, session ID, prompt, is_bash; bash entries populate ToolCommand |
| Session | <session-id>/summary.json | Session summary | Parsed | Title, times, cwd, model, Git branch/commit, agent mode, sandbox profile, reasoning effort |
| Session | <session-id>/updates.jsonl | Update stream | Parsed | Chunks, tool calls (rawInput), outputs (rawOutput), stop reason, token usage |
| Session | <session-id>/chat_history.jsonl | Normalized conversation | Parsed (fallback) | Used when timestamped updates absent |
| Session | <session-id>/hunk_records.jsonl | File-hunk records | Parsed | Path, added/removed lines, prompt index, hunk ID, author, timestamp |
| Session | <session-id>/terminal/call-*.log | Terminal output | Parsed | Per call UUID; file mtime is fallback, not command start |
| Session | <session-id>/events.jsonl, signals.json, prompt_context.json | Lifecycle/context | Parsed | Lifecycle, performance, upload counters; prompt bodies as length + SHA-256 |
| Config | config.toml, trusted_folders.toml, version.json, agent_id | Settings, trust, identity | Parsed (redacted) | Permission/model settings, trust decisions with decided_at, version, agent identity |
| Config | worktrees.db (+WAL/SHM) | Worktrees | Parsed | Worktree path, repo, ref/commit, creating session, times, status |
| Config | long-running-background-tasks/, upload/automation state | Background tasks | Hashed inventory | Definition proves configuration, not execution |
| Outside session tree | sessions/session_search.sqlite | session_docs + FTS5 index | Parsed (session_search) | Mirrors transcripts; survives session directory deletion; last_indexed_offset below body length = partial |
| Outside session tree | logs/unified.jsonl | Tool-exec log | Parsed (log_tool_exec) | Tool name, success/failure, duration per sid; no command string; correlate MessageId to updates.jsonl |
| Outside session tree | active_sessions.json | Open sessions | Parsed | session_id to pid, cwd, opened_at |
| Excluded | ~/.grok/auth.json, mcp_credentials.json | Credential stores | Excluded | Never copied into timeline rows |
| Excluded | ~/.grok/memtrace/*.jsonl | Memory profiler samples | Not parsed | rss/alloc samples only; no conversation content |

### Grok Bot

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| Daemon home | ~/.grokbot/settings.json | Settings | Parsed (grokbot_settings) | localToolPermission (always = no prompt), egress tunnel, WebAuthn proxy, MCP box servers |
| Daemon home | ~/.grokbot/local-exec-daemon.json, local-exec-supervisor.json | Daemon state | Parsed | Daemon pid + startedAt; supervisor heartbeat |
| Daemon home | ~/.grokbot/local-exec-daemon.log (+ .log.N) | Daemon logs | Parsed / summarised | No timestamps; [shell-exec] lifecycle only; no command, request ID, exit status |
| Daemon home | local-exec-daemon-credential.json, -connection.json | Credentials | Inventory only | Name, size, mtime; never read |
| Electron profile | Application Support/Grok Bot/sand-client-persistence/<base32>.blob | Transcript replicas | Parsed | Client copy of each agent's cloud transcript: prompts, replies, local-tool permission requests, approvals, journals, widgets, attachments, automation events |
| Electron profile | Application Support/Grok Bot/sentry/scope_v3.json, session.json | App identity | Parsed | Account ID and email, app/macOS version, hardware, timezone, last boot, open agent |
| Electron profile | Application Support/Grok Bot/Local State | Profile creation stamp | Parsed (app_profile_created) | Not conclusive first-install evidence |
| Electron profile | Application Support/Grok Bot/link-preview-cache/link-cache/*.json | Link previews | Parsed (link_preview) | Title, site, fetchedAt; does not prove click or page access |
| Electron profile | sand-secrets.json, gateway-descriptor.json, box-secrets-push-state.v1.json | Secrets/gateway | Inventory only | Never read |

### Other supported apps

| Component | Path | Artifact | Evidence status | Forensic value / notes |
| --- | --- | --- | --- | --- |
| GitHub Copilot CLI | $COPILOT_HOME or ~/.copilot/ | Sessions, command history, plans/checkpoints, session-store.db metadata | Parsed | Auth/MCP secrets excluded |
| GitHub Copilot (VS Code) | Code/User/workspaceStorage/<hash>/chatSessions/ | Chat sessions | Parsed | Also Insiders, VSCodium, emptyWindowChatSessions |
| Windsurf | Windsurf/User/workspaceStorage/*/state.vscdb | VS Code-family chat store | Parsed; Cascade .pb inventory-only | Cascade bundles not decoded |
| Continue | ~/.continue/sessions/*.json | Session JSON | Parsed | Prompts/responses mapped to workspace directory |

## What survives deletion

Artifacts that outlive the conversation they came from — the collection targets for proving that something existed and was removed.

| App | Artifact | Why it matters | RecordType |
| --- | --- | --- | --- |
| Grok Build | sessions/session_search.sqlite | Mirrors transcript text; survives deleting the session directory | session_search |
| Grok Build | logs/unified.jsonl | Proves a tool ran (name, outcome, duration); never the command | log_tool_exec |
| Grok Build | active_sessions.json | Sessions open at acquisition (pid, cwd, opened_at) | - |
| Claude Desktop | deleted_<session-uuid> tombstone | Dated proof a conversation was removed; content not recoverable | session_deleted |
| Claude Desktop | pending-uploads/ | Files staged for upload outlive the chat | pending_upload |
| Claude Desktop | plan-usage-history.json | Presence windows of the app | (derived) |
| Codex | memories/ (git repo), rollout_summaries/ | Summaries and memory outlive rollouts and UI clearing | thread_memory, agent_memory |
| Codex | logs*.sqlite | Prompt text in tracing log independent of rollouts | - |
| Cursor | conversation-search.db | Indexed body text may remain after transcript file is gone | - |
| Gemini CLI | chats JSONL history lane | Rewound/superseded messages remain recoverable | history_*, history_rewind, history_set_messages |
| Grok Bot | sand-client-persistence replicas | Window fixed at last 200 entries / 768 KiB / 24 agents / 7 days; launch triggers pruning | transcript_replica |

## Limitations and blind spots

| App | Limitation |
| --- | --- |
| All | Browser-only ChatGPT, Claude, Grok, Copilot or Gemini use is hint-only; collect the browser profile separately. |
| All | Merged imports bound very large FullText to 8 KiB per row and disclose truncation; profile extracts stop at 3,000,000 rows. |
| All | Credential stores (auth.json, .credentials.json, oauth_creds.json, Login Data, Cookies) are inventoried or excluded, never copied. |
| Claude | Tombstones prove existence and removal time only; pending-uploads rows are inventory only; usage windows are derived. |
| ChatGPT | conversations-v2/v3 bundles are inventoried, not decoded; newer builds may keep chat text cloud-only. |
| ChatGPT Computer History | A credential row proves entry of a password, not its value; recording scope cannot be read from ComputerUseAppApprovals.json; Analytics.db is usually empty. |
| Codex | Thread bodies live under ~/.codex, not the Electron profile; Skysight summaries are model interpretation. |
| Cursor | Composer/workspace recovery needs SQLite support; encrypted/proprietary stores beyond listed paths not claimed. |
| Gemini | Official Gemini macOS desktop app is not parsed; only Gemini CLI. |
| Grok | Consumer grok.com/X chats have no native parser. |
| Grok Build | log_tool_exec is not evidence of what was executed; prompt_context bodies are hashed; memtrace is not parsed. |
| Grok Bot | Daemon log has no timestamps or commands; a permission request or approval does not prove execution; replica window cannot be changed; only macOS (0.43.0) qualified. |

## Importing into AI-Forensics

| App | How to import into AI-Forensics | Notes |
| --- | --- | --- |
| Claude Code | ai-forensics collect --mode folder --path <folder containing .claude> | Supported parser. Use --mode machine to scan this PC; --include-subagents to include sidechains. |
| OpenAI Codex | ai-forensics collect --mode folder --path <~/.codex> | Supported parser. Rollout transcripts, session index and prompt history. |
| Cursor | ai-forensics collect --mode folder --path <~/.cursor or Cursor User folder> | Supported parser. Agent transcripts plus SQLite composer/workspace chats. |
| Gemini CLI | ai-forensics collect --mode folder --path <~/.gemini> | Supported parser. Chats, shell history and legacy JSON consolidate into one timeline. |
| GitHub Copilot | ai-forensics collect --mode folder --path <~/.copilot or Code/User folder> | Supported parser. Copilot CLI sessions and VS Code chatSessions. |
| ChatGPT Desktop / Atlas | Reference only - no parser in the current build | Documented here for future ingestion; browser-only use is hint-only. |
| ChatGPT Computer History | Reference only - no parser in the current build | High-value event stream; candidate for a future parser. |
| Grok Build / Grok Bot | Reference only - no parser in the current build | Session trees, search index and replicas documented for future parsers. |
| All collected cases | ai-forensics detect --case <id> | Runs the 12 deterministic detectors over every stored row. |
| All collected cases | ai-forensics analyze and ai-forensics rank (optional), then ai-forensics serve | Local-model explanations and advisory ranking; review and export in the web UI. |

---

Created by [Sanjeet Sharma](https://www.linkedin.com/in/sanjeet-sharma-cissp-17b68570/).