/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.http;

import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.authtoken.jwt.JwtVendor;

import static java.util.Objects.requireNonNull;

class OnBehalfOfJwtAuthorizationHeaderFactory {

	private final String issuer;
	private final String subject;
	private final String audience;
	private final List<String> roles;
	private final List<String> backendRoles;
	private final String encryption_key;
	private final String signing_key;
	private final String headerName;
	private final Integer expirySeconds;


	public OnBehalfOfJwtAuthorizationHeaderFactory(String signing_key, String issuer, String subject, String audience, List<String> roles, List<String> backendRoles, Integer expirySeconds, String headerName, String encryption_key) {
		this.signing_key = requireNonNull(signing_key, "Signing key is required");
		this.issuer = requireNonNull(issuer, "Issuer is required");
		this.subject = requireNonNull(subject, "Subject is required");
		this.audience = requireNonNull(audience, "Audience is required.");
		this.roles = requireNonNull(roles, "Roles claim is required");
		this.backendRoles = requireNonNull(backendRoles, "Backend roles claim is required");
		this.expirySeconds = requireNonNull(expirySeconds, "Expiry is required");
		this.headerName = requireNonNull(headerName, "Header name is required");
		this.encryption_key = encryption_key;
	}

	Header generateValidToken() throws Exception {
		Optional<LongSupplier> currentTime = Optional.of(() -> System.currentTimeMillis() / 1000);
		Settings settings = Settings.builder().put("signing_key", signing_key).put("encryption_key", encryption_key).build();
		JwtVendor jwtVendor = new JwtVendor(settings, currentTime);
		String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles);

		return toHeader(encodedJwt);
	}

	private BasicHeader toHeader(String token) {
		return new BasicHeader(headerName, "Bearer " + token);
	}
}
