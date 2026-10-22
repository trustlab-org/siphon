<p align="center">
  <img src="res/siphon-svg.svg" alt="siphon" width="260">
</p>

<p align="center">
  A lightweight, single-binary collector that pulls logs from cloud and SaaS platforms into Kafka, S3, Opensearch
</p>

## Features

- Google Workspace audit logs from the Admin SDK Reports API: 14 log types, including login, admin, OAuth tokens, Drive, Gmail and SAML.
- One cursor per log type. A cursor moves forward only after the output confirms every event in the window.
- Late events are caught: each poll re-checks the last few minutes, and a periodic sweep reaches back further per log type.
- Deterministic event IDs for deduplication, also used as the Kafka message key.
- API responses are kept as received; nested parameters are flattened into a `params` object.
- Exponential backoff on rate limits and server errors. Log types the tenant's plan does not offer are re-checked hourly.
- Prometheus metrics per log type: events sent, late events, poll errors and cursor lag.
- Any Bento output: Kafka, S3, OpenSearch, Elasticsearch, HTTP or files.
- One static binary, configured with a YAML file and an env file. No runtime to install.

## Installation

Requires Go 1.27+.

```bash
go build -o bin/siphon ./cmd/collector
```

## Google Workspace setup

A super admin account is needed for these steps

### 1. Create a reports user

1. In the [Admin console](https://admin.google.com), go to [Directory, Users](https://admin.google.com/ac/users), Add new user, for example `reports@your-domain`.
2. Sign in once as this user and accept the terms. Set a long password and store it; Siphon does not use it.
3. Go to [Account, Admin roles](https://admin.google.com/ac/roles), Create new role. Name it "Reports reader" and select only the Reports privilege.
4. Assign the role to the reports user.

### 2. Create a service account and key

1. In [Google Cloud console](https://console.cloud.google.com), signed in as the super admin and create inside your organization.
2. Go to APIs & Services, Library and enable the [Admin SDK API](https://console.cloud.google.com/apis/library/admin.googleapis.com).
3. Go to [IAM & Admin, Service accounts](https://console.cloud.google.com/iam-admin/serviceaccounts), Create service account. Do not grant it any roles.
4. Open the service account then Keys, there Create new key, JSON. The key file downloads.
5. If key creation is blocked, the [organization policy](https://console.cloud.google.com/iam-admin/orgpolicies) "Disable service account key creation" is on. Override it for this project only, create the key, then set the policy back to "Inherit parent's policy". The key keeps working.
6. Copy the service account's Unique ID from its details page.

### 3. Allow domain-wide delegation

1. In the Admin console, go to Security, Access and data control, API controls, [Manage Domain Wide Delegation](https://admin.google.com/ac/owl/domainwidedelegation), Add new.
2. Client ID: the Unique ID from step 2.6.
3. OAuth scope: `https://www.googleapis.com/auth/admin.reports.audit.readonly`
4. Authorize.

### 4. Run

1. Save the key as `secrets/google-sa.json` and restrict it: `chmod 600 secrets/google-sa.json`. Never commit it.
2. Copy the settings template and fill it in:

   ```bash
   cp deploy/gws/gws.env.example deploy/gws/gws.env
   ```

   Set `GWS_ADMIN_SUBJECT` to the reports user, and `KAFKA_BROKERS` and `KAFKA_TOPIC` for your Kafka.
3. Start Siphon:

   ```bash
   ./bin/siphon -e deploy/gws/gws.env -c config/google-workspace.yaml
   ```
