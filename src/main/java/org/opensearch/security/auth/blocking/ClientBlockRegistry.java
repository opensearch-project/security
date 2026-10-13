/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2015-2019 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.auth.blocking;

import java.util.Set;

public interface ClientBlockRegistry<ClientIdType> {

    /**
     * @return true iff the given clientId is currently blocked (i.e. an active block exists and has not expired).
     */
    boolean isBlocked(ClientIdType clientId);

    /**
     * Block the given clientId for the registry's default block duration.
     * Implementations compute an absolute expiry from the current time and their configured block duration.
     */
    void block(ClientIdType clientId);

    /**
     * Block the given clientId until the given absolute epoch time (milliseconds since epoch).
     * Used when the expiry is known independently of the local registry — e.g. when hydrating from a
     * shared source, or when a peer node propagates a block issued elsewhere.
     * <p>
     * Implementations MAY enforce a safety upper bound on the effective block duration (e.g. a
     * cache-wide max age), in which case the actual expiry is {@code min(expiresAtMs, writeTime + maxAge)}.
     *
     * @param clientId     the client to block
     * @param expiresAtMs  absolute epoch time (ms) at which the block should expire; a value in the
     *                     past MUST NOT cause the client to become blocked
     */
    void block(ClientIdType clientId, long expiresAtMs);

    /**
     * Remove any active block for the given clientId. No-op if the client is not blocked.
     */
    void unblock(ClientIdType clientId);

    /**
     * @return the absolute epoch time (ms) at which the current block expires, or {@code null} if the
     *         client is not currently blocked.
     */
    Long expiresAtMs(ClientIdType clientId);

    /**
     * @return a snapshot of all clientIds currently blocked at this registry. Bounded by the registry's
     *         {@code max_blocked_clients}. The returned set is a snapshot and may be stale immediately.
     */
    Set<ClientIdType> currentlyBlocked();

    Class<ClientIdType> getClientIdType();
}
