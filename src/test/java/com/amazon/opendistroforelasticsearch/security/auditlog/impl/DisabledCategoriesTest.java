/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.test.AbstractSecurityUnitTest;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MockRestRequest;
import com.amazon.opendistroforelasticsearch.security.auditlog.integration.TestAuditlogImpl;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.base.Joiner;
import org.junit.rules.ExpectedException;

public class DisabledCategoriesTest {

    ClusterService cs = mock(ClusterService.class);
    DiscoveryNode dn = mock(DiscoveryNode.class);

	@Rule
	public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setup() {
        when(dn.getHostAddress()).thenReturn("hostaddress");
        when(dn.getId()).thenReturn("hostaddress");
        when(dn.getHostName()).thenReturn("hostaddress");
        when(cs.localNode()).thenReturn(dn);
        when(cs.getClusterName()).thenReturn(new ClusterName("cname"));
        TestAuditlogImpl.clear();
    }

	@Test
	public void invalidRestCategoryConfigurationTest() {
		thrown.expect(IllegalArgumentException.class);

		Builder settingsBuilder = Settings.builder();
		settingsBuilder.put("opendistro_security.audit.type", TestAuditlogImpl.class.getName());
        settingsBuilder.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "nonexistent");
        new AuditLogImpl(settingsBuilder.build(), null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
	}

	@Test
	public void invalidTransportCategoryConfigurationTest() {
		thrown.expect(IllegalArgumentException.class);

		Builder settingsBuilder = Settings.builder();
		settingsBuilder.put("opendistro_security.audit.type", TestAuditlogImpl.class.getName());
		settingsBuilder.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "nonexistent");
		new AuditLogImpl(settingsBuilder.build(), null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
	}

	@Test
	public void invalidConfigurationTest() {
		Builder settingsBuilder  = Settings.builder();
		settingsBuilder.put("opendistro_security.audit.type", "debug");
		settingsBuilder.put("opendistro_security.audit.config.disabled_categories", "nonexistant, bad_headers");
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
		logAll(auditLog);
		String result = TestAuditlogImpl.sb.toString();
		Assert.assertFalse(categoriesPresentInLog(result, AuditCategory.BAD_HEADERS));
	}

	@Test
	public void enableAllCategoryTest() throws Exception {
		final Builder settingsBuilder  = Settings.builder();

		settingsBuilder.put("opendistro_security.audit.type", TestAuditlogImpl.class.getName());
		settingsBuilder.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE");
        settingsBuilder.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE");

		// we use the debug output, no ES client is needed. Also, we
		// do not need to close.
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);

		logAll(auditLog);

		// we're using the ExecutorService in AuditLogImpl, so we need to wait
		// until all tasks are finished before we can check the result
		auditLog.close();

		String result = TestAuditlogImpl.sb.toString();

		Assert.assertTrue(AuditCategory.values()+"#"+result, categoriesPresentInLog(result, filterComplianceCategories(AuditCategory.values())));

		Assert.assertThat(result, containsString("testuser.transport.succeededlogin"));
		Assert.assertThat(result, containsString("testuser.rest.succeededlogin"));
		Assert.assertThat(result, containsString("testuser.rest.failedlogin"));
		Assert.assertThat(result, containsString("testuser.transport.failedlogin"));
		Assert.assertThat(result, containsString("privilege.missing"));
		Assert.assertThat(result, containsString("action.indexattempt"));
		Assert.assertThat(result, containsString("action.transport.ssl"));
		Assert.assertThat(result, containsString("action.success"));
		Assert.assertThat(result, containsString("Empty"));
	}

	@Test
	public void disableSingleCategoryTest() throws Exception {
		for (AuditCategory category : AuditCategory.values()) {
		    TestAuditlogImpl.clear();
			checkCategoriesDisabled(category);
		}
	}

	@Test
	public void disableAllCategoryTest() throws Exception{
		checkCategoriesDisabled(AuditCategory.values());
	}

	@Test
	public void disableSomeCategoryTest() throws Exception{
		checkCategoriesDisabled(AuditCategory.AUTHENTICATED, AuditCategory.BAD_HEADERS, AuditCategory.FAILED_LOGIN);
	}

	/*@After
	public void restoreOut() {
		System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
	}*/

	protected void checkCategoriesDisabled(AuditCategory... disabledCategories) throws Exception {

		List<String> categoryNames = new LinkedList<>();
		for (AuditCategory category : disabledCategories) {
			categoryNames.add(category.name().toLowerCase());
		}
		String disabledCategoriesString = Joiner.on(",").join(categoryNames);

		Builder settingsBuilder  = Settings.builder();
		settingsBuilder.put("opendistro_security.audit.type", TestAuditlogImpl.class.getName());
		settingsBuilder.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, disabledCategoriesString);
        settingsBuilder.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, disabledCategoriesString);


		// we use the debug output, no ES client is needed. Also, we
		// do not need to close.
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);

		logAll(auditLog);

		auditLog.close();

		String result = TestAuditlogImpl.sb.toString();

		List<AuditCategory> allButDisablesCategories = new LinkedList<>(Arrays.asList(AuditCategory.values()));
		allButDisablesCategories.removeAll(Arrays.asList(disabledCategories));

		System.out.println(result+"###"+disabledCategoriesString);
		Assert.assertFalse(categoriesPresentInLog(result, disabledCategories));
		Assert.assertTrue(categoriesPresentInLog(result, filterComplianceCategories(allButDisablesCategories.toArray(new AuditCategory[] {}))));
	}

	protected boolean categoriesPresentInLog(String result, AuditCategory... categories) {
		// since we're logging a JSON structure, whitespaces between keys and
		// values must not matter
		result = result.replaceAll(" ", "");
		for (AuditCategory category : categories) {
			if(!result.contains("\""+AuditMessage.CATEGORY+"\":\""+category.name()+"\"")) {
				System.out.println("MISSING: "+category.name());
			    return false;
			}
		}
		return true;
	}

	protected void logAll(AuditLog auditLog) {
		//11 requests
	    logRestFailedLogin(auditLog);
		logRestBadHeaders(auditLog);
		logRestSSLException(auditLog);
		logRestSucceededLogin(auditLog);

		logMissingPrivileges(auditLog);
		logSecurityIndexAttempt(auditLog);
		logAuthenticatedRequest(auditLog);

		logTransportSSLException(auditLog);
		logTransportBadHeaders(auditLog);
		logTransportFailedLogin(auditLog);
		logTransportSucceededLogin(auditLog);
    }

	 protected void logRestSucceededLogin(AuditLog auditLog) {
	     auditLog.logSucceededLogin("testuser.rest.succeededlogin", false, "testuser.rest.succeededlogin", new MockRestRequest());
	 }

	 protected void logTransportSucceededLogin(AuditLog auditLog) {
	     auditLog.logSucceededLogin("testuser.transport.succeededlogin", false, "testuser.transport.succeededlogin", new TransportRequest.Empty(), "test/action", new Task(0, "x", "ac", "", null, null));
	 }


    protected void logRestFailedLogin(AuditLog auditLog) {
    	auditLog.logFailedLogin("testuser.rest.failedlogin", false, "testuser.rest.failedlogin", new MockRestRequest());
    }

    protected void logTransportFailedLogin(AuditLog auditLog) {
    	auditLog.logFailedLogin("testuser.transport.failedlogin", false, "testuser.transport.failedlogin", new TransportRequest.Empty(), null);
    }

    protected void logMissingPrivileges(AuditLog auditLog) {
    	auditLog.logMissingPrivileges("privilege.missing", new TransportRequest.Empty(), null);
    }

    protected void logTransportBadHeaders(AuditLog auditLog) {
    	auditLog.logBadHeaders(new TransportRequest.Empty(),"action", null);
    }

    protected void logRestBadHeaders(AuditLog auditLog) {
    	auditLog.logBadHeaders(new MockRestRequest());
    }

    protected void logSecurityIndexAttempt(AuditLog auditLog) {
    	auditLog.logSecurityIndexAttempt(new TransportRequest.Empty(), "action.indexattempt", null);
    }

    protected void logRestSSLException(AuditLog auditLog) {
    	auditLog.logSSLException(new MockRestRequest(), new Exception());
    }

    protected void logTransportSSLException(AuditLog auditLog) {
    	auditLog.logSSLException(new TransportRequest.Empty(), new Exception(), "action.transport.ssl", null);
    }

    protected void logAuthenticatedRequest(AuditLog auditLog) {
    	auditLog.logGrantedPrivileges("action.success", new TransportRequest.Empty(), null);
    }

    private static final AuditCategory[] filterComplianceCategories(AuditCategory[] cats) {
        List<AuditCategory> retval = new ArrayList<AuditCategory>();
        for(AuditCategory c: cats) {
            if(!c.toString().startsWith("COMPLIANCE")) {
                retval.add(c);
            }
        }
        return retval.toArray(new AuditCategory[0]);
    }

}
