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

package com.amazon.dlic.auth.ldap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.junit.Assert;
import org.junit.Test;

import com.amazon.dlic.auth.ldap.util.Utils;

public class UtilsTest {


    @Test
    public void testLDAPName() throws Exception {
        //same ldapname
        Assert.assertEquals(new LdapName("CN=1,OU=2,O=3,C=4"),new LdapName("CN=1,OU=2,O=3,C=4"));

        //case differ
        Assert.assertEquals(new LdapName("CN=1,OU=2,O=3,C=4".toLowerCase()),new LdapName("CN=1,OU=2,O=3,C=4".toUpperCase()));

        //case differ
        Assert.assertEquals(new LdapName("CN=abc,OU=xyz,O=3,C=4".toLowerCase()),new LdapName("CN=abc,OU=xyz,O=3,C=4".toUpperCase()));

        //same ldapname
        Assert.assertEquals(new LdapName("CN=a,OU=2,O=3,C=xxx"),new LdapName("CN=A,OU=2,O=3,C=XxX"));

        //case differ and spaces
        Assert.assertEquals(new LdapName("Cn =1 ,OU=2, O = 3,C=4"),new LdapName("CN= 1,Ou=2,O=3,c=4"));

        //same components, different order
        Assert.assertNotEquals(new LdapName("CN=1,OU=2,C=4,O=3"),new LdapName("CN=1,OU=2,O=3,C=4"));

        //last component missing
        Assert.assertNotEquals(new LdapName("CN=1,OU=2,O=3"),new LdapName("CN=1,OU=2,O=3,C=4"));

        //first component missing
        Assert.assertNotEquals(new LdapName("OU=2,O=3,C=4"),new LdapName("CN=1,OU=2,O=3,C=4"));

        //parse exception
        try {
            new LdapName("OU2,O=3,C=4");
            Assert.fail();
        } catch (InvalidNameException e) {
            //expected
        }
    }
}
