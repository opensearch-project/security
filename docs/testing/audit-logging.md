# Audit logging tests

Audit tests should describe which events a request produces, not just whether selected words occur somewhere in the output.

## Assert structured events

- Assert category, effective user, origin, layer, and action or REST path together on the same `AuditMessage`.
- Select events by their meaning, not arrival order. REST authentication and transport authorization are different events.
- Assert exact counts when the scenario has a fixed event contract. Include unexpected categories and duplicates in the check, rather than filtering them away first.
- Keep explicit negative checks for credentials and other fields that must not be logged.
- Check variable values by their relationships. A transport task ID should contain the emitting node's ID and a nonnegative numeric task ID; separate requests should have distinct task IDs. Comparing an ID with itself proves nothing.

`BasicAuditlogTest.testDefaultsRest` and `testTaskId` provide examples for a search producing one REST authentication event and one transport privilege event with their configured audit filters.

## Capture and asynchronous completion

Start capturing after setup and before issuing the request. Prefer action-scoped capture over the deprecated shared string buffer in `TestAuditlogImpl`. Arbitrary sleeps in the test do not establish completion.

The existing helpers still have limitations:

- `TestAuditlogImpl.doThenWaitForMessages` waits for a count and then checks a short late-message window. It uses shared static state and timing internally; it is not a deterministic sink-drain barrier.
- `AuditLogsRule.assertExactly` succeeds as soon as the matching count is observed. It does not prove that another matching event cannot arrive later.
- Expecting zero messages requires a defined observation boundary, not an immediately satisfied zero-count assertion.

Do not describe either helper as proof that no arbitrarily late events can arrive. A follow-up should add an explicit completion/drain mechanism or request-scoped capture with a well-defined completion boundary, including tests that deliberately delay duplicate events. Avoid changing shared helpers globally before their callers and asynchronous sinks are understood.

## Choosing scope

Keep setup traffic separate from the operation under test. For multi-request scenarios, use a supported request correlation identifier where available and verify propagation across the expected layers. Node IDs, timestamps, and task IDs must not be normalized away if their relationship is what the test checks.

Global counts may legitimately vary with shard fan-out, retries, and background work. Isolate request-level behavior, or explicitly describe permitted variability. Do not replace every lower-bound assertion with equality mechanically.

## Running the initial examples

```sh
./gradlew :test --tests '*BasicAuditlogTest.testDefaultsRest' --tests '*BasicAuditlogTest.testTaskId'
./gradlew :test --tests '*BasicAuditlogTest'
```

The legacy cluster-backed suite is under `src/test`, whereas `SearchOperationTest` and `AuditLogsRule` are under `src/integrationTest` and use `:integrationTest`.
