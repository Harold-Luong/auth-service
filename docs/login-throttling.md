# Login throttling

`POST /api/v1/auth/login` reserves an account budget and an IP budget before
looking up the user or checking the password. Both reservations are atomic within
one application instance. Email keys are trimmed and lowercased with `Locale.ROOT`.
Unknown accounts are limited in the same way as existing accounts.

Defaults in `application.yaml`:

```yaml
auth:
  login-throttle:
    account-max-attempts: 10
    ip-max-attempts: 50
    window: 15m
    max-keys: 10000
```

These are fixed windows starting with the first admitted attempt for each key.
Every admitted login attempt counts, including successful logins. Success does
not reset either budget. Rejected requests do not consume budgets or extend their
windows. Validation failures (`400`) occur before the login service and do not
consume budgets; this limiter does not replace HTTP-level flood protection.

Exceeding either budget returns HTTP `429`, a `Retry-After` header in whole seconds,
and the usual error body:

```json
{"code":"429","message":"Too many login attempts. Please try again later."}
```

The budgets are held in memory and reset on restart. They are **not shared across
replicas**. For multiple instances, move both counters to a shared store with atomic
updates (for example Redis), or enforce corresponding limits at a shared gateway.
The store contains at most `max-keys` account/IP entries. Expired entries are pruned
on incoming attempts; at capacity, requests needing new keys return `429` until
space expires. Active entries are not evicted to admit attacker-controlled keys.

## Client IP and proxies

The controller uses `HttpServletRequest.getRemoteAddr()`. The default configuration
sets `server.forward-headers-strategy: none`; the application does not parse
`X-Forwarded-For` or `Forwarded` supplied by callers. Behind a reverse proxy this
means the proxy IP is used, so users behind that proxy share the IP budget.

Before deploying behind a proxy, either apply IP throttling at that proxy/gateway,
or explicitly configure trusted proxy processing in the servlet container so
`getRemoteAddr()` reflects the client. Restrict direct access to the application
and make the trusted proxy overwrite incoming forwarding headers. Do not simply
trust arbitrary forwarding headers from public requests.

## Failed-login events

Logger `auth.login.audit` emits `WARN` events with the logging framework's timestamp:

```text
event=login_failed accountHash=<SHA-256 of normalized email> ip=<remote IP> reason=INVALID_PASSWORD
event=login_throttled accountHash=<hash> ip=<remote IP> retryAfterSeconds=900
```

Failure reasons are `UNKNOWN_ACCOUNT`, `INVALID_PASSWORD`, and `INACTIVE_ACCOUNT`.
These events survive rollback of the login database transaction. Passwords, password
hashes, tokens, raw emails and request bodies are not included in these audit events.
The account hash is a correlation identifier, not guaranteed anonymization.
Server/database failures are not mislabeled as bad credentials. Invalid request
bodies are handled by validation and are not login-failure audit events.

Events go to the application's configured log appenders, not a database audit table.
Configure log collection, restricted access, retention and alerts in the deployment;
high request volume can also create high log volume.

Design references: [OWASP authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling)
and [OWASP logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude).
