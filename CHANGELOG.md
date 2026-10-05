# Changelog

All notable changes are documented here. Versioning follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] — Open-source release

First public release by CyberPanda under the MIT License.

### Open-source preparation
- English is now the main language of the code, server messages, legal pages and documentation; other languages stay available via `lang/`
- Single source tree (no duplicated deployment copies); Docker, systemd, Caddy and nginx examples under `deploy/`
- Removed hosting-panel specific tooling and the obfuscated client build
- Open defaults: test mode and closed-circle mode are off, the PPScript manual is public
- Routes `/imprint`, `/privacy`, `/terms`; default rooms renamed to Plaza, Lounge, Cinema, Studio, Gallery
- Added README, CONTRIBUTING, SECURITY and LEGAL documents

### Earlier 1.0.0 feature set

### Chat and avatars
- Avatars scale with the room, independent of display size
- Up to 12 layered overlay avatars, no placeholder circle when worn
- Avatar bag: unlimited, categories with rename and delete, sorting,
  cut-out editor, drop avatars into the room
- Speech bubbles hug their text; movement makes them fade faster so nobody
  can park long texts in a room
- Away mode (AFK) with a freely chosen message and a running timer

### Rooms
- Stable room IDs, landing room with sub-rooms
- Doors: passage or lock, editable in a floating window, own image, opacity,
  optional label, free-standing graphics
- Lock square opens automatically when the creator leaves
- `::newroom`, `::showroom`, `::hideroom`

### Guilds and clans
- Custom rank names and a rights matrix per tier
- Renown from online time, size and investment; unlocks which perks may be
  bought
- Perks with individual runtimes, group treasury, point donations
- Leaderboard by renown, treasury, members, online, activity
- Guild chat readable only by members, across rooms

### Media
- Watch together: share in room plays for everyone at once
- Watch alone, audio-only mode, per-user opt-out
- Video scales with the window

### Moderation and privacy
- Three logging modes: `full`, `events` (no message content), `off`
- Automatic deletion of old logs after a configurable number of days
- Admin panel: filter logs by person and period, CSV export for GDPR
  access requests
- Imprint, privacy policy and terms of use, generated from configuration and
  matching the active logging mode

### Scripting
- PPScript replaces the old stack language: line based, one command per line
- Events ENTER, LEAVE, SAY, DOOR, TIMER
- Live syntax checking in the editor, manual and admin wiki

### Accounts and security
- Name registry: every member name belongs to exactly one account and stays
  reserved; renaming carries groups, ranks, points and rights along
- Short random guest names
- Optional sign-in with Google and Apple (OpenID Connect, RS256 verified)
- Brute-force protection on role authentication, constant-time comparisons

### Interface
- Nine languages, switchable at runtime, English as fallback
- Own context menu everywhere, including copy and paste in text fields
- Command suggestions after `::`, filtered by rank
- Floating windows freely movable and resizable, never behind the toolbar
