/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.test.framework.TestSecurityConfig.Role;

import static java.util.Objects.requireNonNull;

public class RolesMapping implements ToXContentObject {
	private String roleName;
	private List<String> backendRoles;
	private List<String> hosts;
	private List<String> users;

	private boolean reserved = false;

	public RolesMapping(Role role) {
		requireNonNull(role);
		this.roleName = requireNonNull(role.getName());
		this.backendRoles = new ArrayList<>();
	}

	public RolesMapping backendRoles(String...backendRoles) {
		this.backendRoles.addAll(Arrays.asList(backendRoles));
		return this;
	}

	public RolesMapping hosts(List<String> hosts) {
		this.hosts = hosts;
		return this;
	}

	public RolesMapping users(List<String> users) {
		this.users = users;
		return this;
	}

	public RolesMapping reserved(boolean reserved) {
		this.reserved = reserved;
		return this;
	}

	public String getRoleName() {
		return roleName;
	}

	@Override
	public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
		xContentBuilder.startObject();
		xContentBuilder.field("reserved", reserved);
		xContentBuilder.field("backend_roles", backendRoles);
		xContentBuilder.endObject();
		return xContentBuilder;
	}
}
