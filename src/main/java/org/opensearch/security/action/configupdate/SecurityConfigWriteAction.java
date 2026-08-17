/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.action.configupdate;

import org.opensearch.action.ActionType;

/**
 * ActionType that persists a Security configuration document to the security index and then
 * broadcasts a {@link ConfigUpdateAction} to every node so each one reloads the affected config.
 *
 * <p>The whole persistence + fan-out lifecycle runs under a single OpenSearch {@link
 * org.opensearch.tasks.Task}. This is what enables clients to submit REST configuration writes
 * with {@code wait_for_completion=false} and monitor progress via the standard Tasks API.
 *
 * <p>The task is intentionally <b>not</b> cancellable: because a mid-fan-out cancellation could
 * leave the security index updated but only a subset of nodes reloaded, the request is only ever
 * allowed to run to completion. See issue #6337 for the design discussion.
 */
public class SecurityConfigWriteAction extends ActionType<SecurityConfigWriteResponse> {

    public static final SecurityConfigWriteAction INSTANCE = new SecurityConfigWriteAction();
    public static final String NAME = "cluster:admin/opendistro_security/api/write_config";

    protected SecurityConfigWriteAction() {
        super(NAME, SecurityConfigWriteResponse::new);
    }
}
