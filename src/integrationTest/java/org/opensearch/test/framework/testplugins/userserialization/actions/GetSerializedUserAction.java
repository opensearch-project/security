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

package org.opensearch.test.framework.testplugins.userserialization.actions;

import org.opensearch.action.ActionType;

public class GetSerializedUserAction extends ActionType<GetSerializedUserResponse> {

    public static final GetSerializedUserAction INSTANCE = new GetSerializedUserAction();
    public static final String NAME = "cluster:admin/userserialization/get_serialized_user";

    protected GetSerializedUserAction() {
        super(NAME, GetSerializedUserResponse::new);
    }
}
