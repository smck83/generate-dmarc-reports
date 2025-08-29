# Generate DMARC Reports

`generate-dmarc-reports` is a lightweight Python application packaged in Docker that **synthesises DMARC aggregate reports** and emails them at a configurable rate.  

This tool is designed to **populate DMARC reporting solutions with demo/test data**. It generates RFC-compatible aggregate report XML files, compresses them (gzip), and sends them via SMTP to any mailbox you specify.  

---

## Key Features

- **Synthetic DMARC aggregate reports** with realistic structure:
  - `<report_metadata>` (org, ID, date range, etc.)
  - `<policy_published>` (your `REPORT_DOMAIN` policy)
  - `<record>` blocks with SPF/DKIM pass/fail combinations
- **Unique reports**: every file has a fresh UUID and current timestamps.
- **SPF include aware**:  
  - IPs for *pass-aligned* records are picked from SPF CIDRs of `SPF_PASS_INCLUDES`.  
  - IPs for *fail records* are picked from SPF CIDRs of `SPF_FAIL_INCLUDES`.  
- **Configurable rate**: send between `MIN_PER_HOUR` and `MAX_PER_HOUR` reports/hour, with jitter to avoid uniform patterns.
- **Gzipped XML attachments** with filenames like:  
  ```
  example.com!<begin>!<end>!<uuid>.xml.gz
  ```
- **Runs anywhere Docker runs**: Linux, Mac, Windows, Portainer, etc.

---

## Example Use Case

You’ve deployed a DMARC reporting analyser (e.g. Mimecast DMARC Analyzer, commercial or self-hosted). You want to:  

- **Demonstrate** the reporting dashboards with live-looking data.  
- **Stress-test** ingestion pipelines with varying report volumes.  
- **Populate** lab/test environments without waiting for real external mail flow.  

This container will generate 100–300 aggregate reports per hour (configurable) and deliver them to your DMARC solution’s reporting inbox.

---

## Usage

### 1. Pull and run with Docker Compose

```bash
docker compose up -d
```

Logs:

```bash
docker compose logs -f dmarc-reporter
```

---

### 2. Portainer Deployment

If using Portainer stacks:  

- Paste the above Compose into the **Web editor**.  
- In the **Environment variables** tab, add the variables directly.  
- You don’t need `env_file:` in Portainer unless you maintain a `.env` on the Docker host.

---

## Environment Variables

| Variable             | Purpose                                                                 | Example                                                   |
|----------------------|-------------------------------------------------------------------------|-----------------------------------------------------------|
| `ORG_NAME`           | The reporting organisation name shown in `<org_name>`                   | `ExampleOrg`                                              |
| `REPORT_DOMAIN`      | Domain being reported on (`policy_published.domain`)                     | `example.org`                                                  |
| `MAIL_FROM`          | Envelope + header From address                                          | `dmarc-reporting@example.org`                                    |
| `MAIL_TO`            | Recipient of reports (DMARC analyzer mailbox)                           | `rua-address@example.com`                   |
| `SMTP_HOST`          | SMTP relay host                                                         | `smtpserver.example.org`                                        |
| `SMTP_PORT`          | SMTP port (587 for STARTTLS, 465 for SMTPS)                             | `587`                                                     |
| `SMTP_USER`          | SMTP auth username                                                      | `your-smtp-username@exampl.org`                                    |
| `SMTP_PASS`          | SMTP auth password                                                      | `supersecret`                                             |
| `USE_SSL`            | Use implicit SSL (SMTPS on 465)                                         | `false`                                                   |
| `USE_STARTTLS`       | Use STARTTLS upgrade (587)                                              | `true`                                                    |
| `MIN_PER_HOUR`       | Minimum reports per hour                                                | `100`                                                     |
| `MAX_PER_HOUR`       | Maximum reports per hour                                                | `300`                                                     |
| `ONCE`               | Send a single report then exit (for smoke tests)                        | `false`                                                   |
| `TZ`                 | Timezone inside container (affects timestamps)                          | `Australia/Sydney`                                        |
| `SPF_PASS_INCLUDES`  | Space-separated list of SPF include domains used to generate **pass** IPs | `sendgrid.net mailgun.org au._netblocks.mimecast.com`     |
| `SPF_FAIL_INCLUDES`  | Space-separated list of SPF include domains used to generate **fail** IPs | `amazonses.com spf.protection.outlook.com`                       |

---

## Behaviour

- At startup, the app resolves the SPF records of the domains in `SPF_PASS_INCLUDES` and `SPF_FAIL_INCLUDES`, following `include:` chains and collecting `ip4:`/`ip6:` ranges.  
- Each generated DMARC report:
  - Chooses one or more source IPs from the pass/fail pools.  
  - Emits SPF/DKIM results accordingly.  
  - Compresses the XML (`.xml.gz`).  
  - Sends via SMTP to `MAIL_TO`.  
- Runs continuously, spacing messages across the hour with jitter.  

---

## One-shot Test

For a quick smoke test:

```bash
docker run --rm   -e ORG_NAME=McKellarCo   -e REPORT_DOMAIN=mck.la   -e MAIL_FROM=dmarc-reports@mck.la   -e MAIL_TO=you@example.com   -e SMTP_HOST=smtp.example.com   -e SMTP_PORT=587   -e SMTP_USER=...   -e SMTP_PASS=...   -e ONCE=true   ghcr.io/smck83/generate-dmarc-reports:latest
```

You’ll get a single `.xml.gz` report in your mailbox.

---

## ⚠️ Notes

- This tool is for **testing and demo purposes only**. Don’t aim it at third-party DMARC mailboxes without permission.  
- Some SMTP providers rate-limit or block repetitive traffic; use an appropriate relay.  
- If SPF domains resolve to large IP blocks, the app samples random hosts — reports won’t reflect actual traffic distribution.  
