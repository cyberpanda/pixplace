# Legal notes for operators

> This file is a checklist, **not legal advice**. Rules differ by country. If in doubt, ask a qualified lawyer.

Running a public chat server can come with obligations (provider identification, privacy notices, content moderation, handling of takedown notices). Pixplace ships template pages to help, but **you are the operator and you are responsible**.

## 1. Fill in the operator details

Edit `palace_config.json` (created on first start in the data directory):

```json
"legal": {
  "operator_name": "Full name or company",
  "operator_address": "Street 1, 12345 City",
  "operator_country": "Country",
  "operator_mail": "contact@your-domain.example",
  "operator_agent": "",
  "hosting": "Hosting provider, address",
  "minage": "16",
  "retention_days": "30"
}
```

The pages `/imprint`, `/privacy` and `/terms` show a warning banner until all `[placeholders]` are replaced.

## 2. Choose your logging mode

Admin panel → Moderation, or `moderation_mode` in the config:

| Mode | Stored |
|---|---|
| `full` | Messages with date, time, room and name (users are told in the chat) |
| `events` | Only technical events (sign-in, room changes, moderation actions) |
| `off` | Nothing – moderation is live filtering only |

Retention is controlled by `log_retention_days`. The privacy page adapts to the selected mode automatically.

## 3. Privacy requests

The admin panel offers an access report (GDPR Art. 15) and complete erasure (Art. 17). Each action is written to a separate legal log.

## 4. Reports

Users can report content with `::page` or the report function. Reports appear in the admin panel. Define who reviews them and how fast.

## 5. Other points to consider

- Minimum age and parental consent rules in your country
- User-uploaded content and copyright (you can delete uploads in the admin panel)
- Cookie/storage notices – Pixplace uses only technically necessary browser storage and no analytics or advertising
- Applicable platform rules for services offered to the public (e.g. the EU Digital Services Act)
