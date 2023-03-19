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

 package org.opensearch.security.action.tenancy;

 import org.opensearch.action.ActionType;
 
 public class MultiTenancyUpdateAction extends ActionType<BooleanSettingRetrieveResponse> {
 
     public static final MultiTenancyUpdateAction INSTANCE = new MultiTenancyUpdateAction();
     public static final String NAME = "securityconfig:admin/config/tenancy/multitenancy_enabled/update";
 
     protected MultiTenancyUpdateAction() {
         super(NAME, BooleanSettingRetrieveResponse::new);
     }
 }
