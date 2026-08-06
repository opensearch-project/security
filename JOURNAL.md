# FGAC Audit Improvements — Design Journal

## Request Pipeline Flow (FGAC Mode)

```
Client sends REST request
    → SecurityRestFilter.handleRequest()
        → Context restore (Netty header verifier stuff)
        → ** Our injection: stash audit_request_id in ThreadContext **
        → Authentication (checkAndAuthenticateRequest)
        → Audit: logSucceededLogin → save() → stamps request ID
        → Authorization
        → SecurityFilter.apply() (transport layer)
            → Audit: logGrantedPrivileges → save() → stamps request ID
            → Audit: logIndexEvent → save() → stamps request ID
            → Chain proceeds to shard
                → ComplianceIndexingOperationListener → save() → stamps request ID
```

The ID is in ThreadContext before any audit event fires. Everything downstream reads from the same ThreadContext — that's why they all get the same ID.

---

## CRUD Granularity for INDEX_EVENT

`audit_transport_request_type` already tells you the request type (IndexRequest, DeleteRequest, etc.). But the problem is how `INDEX_EVENT` works today:

```java
// AbstractAuditLog.logIndexEvent()
public void logIndexEvent(String privilege, TransportRequest request, Task task) {
    if (!privilege.startsWith("indices:admin/")) {
        return;  // Only logs indices:admin/* actions!
    }
    // Logs as category: INDEX_EVENT
}
```

**Issues:**
1. INDEX_EVENT only fires for `indices:admin/*` — create index, delete index, aliases. NOT for doc writes/reads.
2. The category name is meaningless — doesn't tell you if it was a create, delete, or settings change.
3. You have to parse `audit_transport_action` string to know what happened.

### Option A: New Categories

`INDEX_EVENT_CREATE`, `INDEX_EVENT_DELETE`, `INDEX_EVENT_SETTINGS`, etc.

| Pro | Con |
|-----|-----|
| Can disable/enable independently | More enum values, more config options |
| Clear in category field | Breaking change for existing users |

### Option B: New Field `audit_operation_type`

Keep INDEX_EVENT but add a field like `"audit_operation_type": "CREATE"` / `"DELETE"` / `"SETTINGS_CHANGE"`.

| Pro | Con |
|-----|-----|
| Backward compatible | Can't disable per-operation via `disabled_categories` |
| No config changes | — |
| Still filterable | — |

**Status:** Pending discussion with mentor.

---

## Log Routing by Category/Role (Attribute-Based Routing)

**Goal:** Support multiple Log4j appenders (or any sink) based on event attributes, so operators can route different event streams to different destinations (e.g., `audit_admin.log` vs `audit_data_access.log`).

### How FGAC Audit Sink Routing Currently Works

1. **Default sink** — configured via `plugins.security.audit.type` (log4j, internal_opensearch, webhook, etc.). ALL events go here unless overridden.

2. **Named endpoints** — defined under `plugins.security.audit.endpoints`:
   ```yaml
   endpoints:
     admin_log4j:
       type: log4j
       config:
         log4j.logger_name: audit_admin
     data_webhook:
       type: webhook
       config:
         webhook.url: https://siem.example.com
   ```

3. **Category-based routing** — `plugins.security.audit.routes` maps categories to endpoints:
   ```yaml
   routes:
     COMPLIANCE_DOC_WRITE:
       endpoints: [data_webhook]
     GRANTED_PRIVILEGES:
       endpoints: [admin_log4j]
   ```

4. **`AuditMessageRouter.route(msg)`** — looks up `msg.getCategory()` in `categorySinks` map. If a mapping exists → sends to those sinks. If not → sends to default sink.

5. **`Log4JSink`** — uses a configurable logger name (default: "audit"). Logs JSON to that Log4j logger. Operators route via `log4j2.properties` appenders.

**Limitation:** Routing is ONLY by category. You can't route based on action type, user, index, or other event attributes without creating new categories for each case.

### What Each Sink Outputs To

| Sink | Destination |
|------|-------------|
| Log4j | Files on disk (JSON lines) |
| Internal OpenSearch | Index (`security-auditlog-*`) |
| External OpenSearch | Remote cluster index |
| Webhook | HTTP POST to URL |
| Kafka | Topic messages |

---

### Approach A: Full Attribute-Based Router (in plugin)

Add a `match` clause to routing rules that evaluates against any field in the audit event:

```yaml
plugins.security.audit.routes:
  admin_actions:
    match:
      audit_transport_action: "indices:admin/*"
    endpoints: [admin_log4j]
  data_writes:
    match:
      audit_category: "GRANTED_PRIVILEGES"
      audit_transport_action: "indices:data/write/*"
    endpoints: [write_webhook]
  sensitive_indices:
    match:
      audit_trace_indices: "pii-*"
    endpoints: [compliance_sink]
```

**Implementation:**
- Define `RoutingRule` class: name, match conditions (field → wildcard pattern), endpoint list
- Parse rules in `AuditMessageRouter.enableRoutes()` from config
- Change `route(msg)` to evaluate rules against `msg.getAsMap()`
- Match semantics: AND within a rule (all conditions must match)
- Evaluation order: first matching rule wins, OR all matching rules (TBD)
- Fallback to default sink if no rule matches
- Old category-only format auto-detected (no `match` key → treat as category match)

| Pro | Con |
|-----|-----|
| Maximum flexibility — route on any field | Complex config format for operators |
| Can split admin vs data access vs compliance | Rule evaluation on every event (perf cost) |
| Single mechanism replaces category routing | Need to handle rule ordering/priority |
| Backward compatible if old format still works | Config validation more complex |
| Works with any sink type (not just Log4j) | Testing all match combinations is harder |

---

### Approach B: Log4j Logger Name Includes Category

Make the Log4j sink use a more specific logger name that includes the category. Let operators use Log4j's native `RoutingAppender` to split files.

```java
// Current: all events go to logger "audit"
auditLogger = LogManager.getLogger("audit");

// New: logger name includes category
auditLogger = LogManager.getLogger("audit." + msg.getCategory().name());
```

Operators configure routing in `log4j2.properties`:
```properties
logger.audit_admin.name = audit.GRANTED_PRIVILEGES
logger.audit_admin.level = INFO
logger.audit_admin.appenderRef.file.ref = AdminAuditFile
```

| Pro | Con |
|-----|-----|
| Minimal code change (~5 lines) | Only works for Log4j sink |
| Operators already know Log4j config | Can only route by category, not arbitrary fields |
| No new config format to design | Requires `log4j2.properties` access |
| Zero performance cost | Less powerful than Approach A |
| No backward compat risk | — |

---

### Approach C: Hybrid

Combine both: attribute-based routing for non-Log4j sinks + category-aware logger names for file-level splitting.

| Pro | Con |
|-----|-----|
| Best of both worlds | More code to write and maintain |
| Log4j users get easy file splitting | Two routing mechanisms to document |
| Webhook/index users get attribute routing | Potential confusion |

---

### Approach D: MDC Enrichment for Log4j

Push event attributes into Log4j's MDC/ThreadContext before logging. Operators use `%X{field}` in their pattern and Log4j `RoutingAppender` to split based on any attribute.

```java
// In Log4JSink.doStore():
ThreadContext.put("audit_category", msg.getCategory().name());
ThreadContext.put("audit_action", msg.getPrivilege());
ThreadContext.put("audit_user", msg.getEffectiveUser());
auditLogger.log(logLevel, msg.toJson());
ThreadContext.clearMap();
```

Operator `log4j2.properties`:
```properties
appender.routing.type = Routing
appender.routing.routes.pattern = $${ctx:audit_category}
appender.routing.routes.route_admin.type = Route
appender.routing.routes.route_admin.key = GRANTED_PRIVILEGES
appender.routing.routes.route_admin.appenderRef.ref = AdminFile
```

| Pro | Con |
|-----|-----|
| Route on ANY attribute via standard Log4j | Only works for Log4j sink |
| Zero custom routing logic in plugin | Operators must understand MDC + RoutingAppender |
| Most flexible Log4j approach | MDC is thread-local — async routing needs care |
| Minimal plugin code | Not available for webhook/index/kafka sinks |

> **Note on sanitization:** Colons in filenames are problematic if routing by action. Sanitize before putting in MDC:
> ```java
> private String sanitizeForFilename(String value) {
>     if (value == null) return "unknown";
>     return value.replaceAll("[:/\\\\*?\"<>|]", "_");
> }
> ```

---

### How B vs D Differ

- **B:** Logger name = `"audit." + category`. Operators split files by category via log4j config. Simple but rigid.
- **D:** Push attributes into Log4j MDC before logging. Operators choose what to split by (category, user, action, anything). Flexible but requires RoutingAppender knowledge.

### Recommendation

| Goal | Approach |
|------|----------|
| Split audit files for different event types | B or D |
| Route to different SIEM endpoints based on event content | A |
| Both | C |

### Plan

- Start with **D** (Log4j MDC enrichment) — covers "route to different files" use case flexibly
- Later: **Approach A** (full attribute router) if needed for webhook/kafka/index routing by attributes

---

## Implementation Notes for Approach D

### Key file: `Log4JSink.java`

The `doStore(AuditMessage msg)` method is where the Log4j logger call lives.

### Event delivery chain:
```
save(msg) → messageRouter.route(msg) → store(sink, msg) → sink.doStore(msg)
```

- `route(msg)` — picks which sink(s) based on category
- `store(sink, msg)` — submits to the async thread pool
- `doStore(msg)` — the actual write (Log4j logger call)

### Gotchas:

1. **Log4j's ThreadContext vs OpenSearch's ThreadContext** — different classes. In `Log4JSink.doStore()`, use `org.apache.logging.log4j.ThreadContext`.
2. **Async routing** — MDC is thread-local. MUST set and clear inside `doStore()` itself (same thread that calls `auditLogger.log()`).
3. **Null values** — `msg.getEffectiveUser()` or `msg.getPrivilege()` can be null. `ThreadContext.put(key, null)` throws NPE. Always default to `"unknown"` or skip.
4. **Performance** — `ThreadContext.put()` and `clearMap()` are cheap (HashMap operations). No concern.
5. **Don't clear too aggressively** — use `ThreadContext.clearMap()` (clears MDC only), not `ThreadContext.clearAll()` (clears MDC + stack).

---

## Sink Improvements (Beyond Routing)

1. **Structured filename with date** — default to `audit-YYYY.MM.dd.log` (like `security-auditlog-YYYY.MM.dd`)
2. **File rotation defaults** — ship sensible defaults for max file size, max history, compression
3. **Per-node file naming** — include node name automatically: `audit-node1-2026.07.17.log`
4. **CSV/NDJSON format option** — worth it

---

## Missing Audit Fields — High-Value Additions for Investigability

Surveyed: AWS CloudTrail, Elasticsearch audit logs, ECS (Elastic Common Schema), OCSF.

These fields exist in other audit systems but are absent from OpenSearch FGAC audit events:

### 1. `user_agent` — Client software identifier
- **Source:** Already in REST headers (`User-Agent`), just not promoted to top-level field.
- **Value:** Identifies client type (curl, opensearch-py, Java high-level client, browser). Detects unusual tooling.
- **Effort:** Trivial — extract from existing headers, add as a named field.

### 2. `user.roles` — Mapped roles at decision time
- **Source:** Available in ThreadContext after privilege evaluation (SecurityFilter).
- **Value:** Answers "WHY was this access granted/denied?" Without it, investigators must separately query the roles API.
- **Effort:** Low — roles are already computed, just not written to the audit event.

### 3. `auth.method` — How the user authenticated
- **Source:** Available from the authentication backend (basic, JWT, SAML, PKI, API key, etc.).
- **Value:** Detects anomalies ("this user normally uses SAML but now used basic auth"). Critical for credential compromise investigations.
- **Effort:** Low — auth backend type is known after authentication completes.

### 4. `event.action` — Normalized CRUD operation type
- **Source:** Derived from `audit_transport_action` string.
- **Value:** Enables simple queries like "show all DELETEs" without parsing action strings. Maps to: CREATE, READ, UPDATE, DELETE, ADMIN, MONITOR.
- **Effort:** Low — just a classification of the existing action string.
- **Note:** This IS the CRUD granularity task for INDEX_EVENT discussed above.

### 5. `event.duration` — Request processing time in milliseconds
- **Source:** Measure time between request entry (SecurityRestFilter) and response.
- **Value:** Detects slow operations, blocked requests, timeout patterns. Correlates with slow logs. Essential for performance-related security investigations. after a certain time log what it has done so far and relay it had been going on for this long
- **Effort:** Medium — requires wrapping the action chain to measure elapsed time.

### 6. `http.response.status_code` — HTTP response code
- **Source:** Available after the REST handler completes (RestChannel response).
- **Value:** Was it 200, 403, 404, 500? A 500 internal error isn't captured as a distinct audit signal today.
- **Effort:** Medium — need to capture after response is written, not at request time.

### Priority for Implementation

| Priority | Field | Effort | Value |
|----------|-------|--------|-------|
| 1 | `user_agent` | Trivial | Medium |
| 2 | `user.roles` | Low | High |
| 3 | `auth.method` | Low | High |
| 4 | `event.action` | Low | High |
| 5 | `event.duration` | Medium | Medium |
| 6 | `http.response.status_code` | Medium | Medium |

---

## Completed Work

- ✅ **Request correlation ID** (`audit_request_id`) — commit `5a609100`, pushed to `origin/fgac-audit-improvements`
- ✅ Integration tests pass (4 tests: correlation, X-Request-Id header, UUID fallback, different IDs per request)
