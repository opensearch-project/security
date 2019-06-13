/*
 * Copyright 2015-2019 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import com.amazon.opendistroforelasticsearch.security.auth.HTTPAuthenticator;

import java.io.IOException;
import java.util.HashMap;

import org.elasticsearch.common.io.stream.StreamInput;
import org.junit.Assert;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;

public class ModuleInfoTests {

    @Test
    public void testGetAsMap1() {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        ModuleInfo moduleInfo = new ModuleInfo(moduleType, "classname");

        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("type", "UNKNOWN");
        hashMap.put("description", "Unknown type");
        hashMap.put("is_advanced_module", "true");
        hashMap.put("default_implementation", null);
        hashMap.put("actual_implementation", "classname");
        hashMap.put("version", "");
        hashMap.put("buildTime", "");
        hashMap.put("gitsha1", "");

        Assert.assertEquals(hashMap, moduleInfo.getAsMap());
    }

    @Test
    public void testGetAsMap2() throws IOException {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        StreamInput streamInput = PowerMockito.mock(StreamInput.class);
        PowerMockito.when(streamInput.readString()).thenReturn("foo");
        PowerMockito.when(streamInput.readEnum(ModuleType.class))
                .thenReturn(moduleType);
        ModuleInfo moduleInfo = new ModuleInfo(streamInput);

        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("type", "UNKNOWN");
        hashMap.put("description", "Unknown type");
        hashMap.put("is_advanced_module", "true");
        hashMap.put("default_implementation", null);
        hashMap.put("actual_implementation", "foo");
        hashMap.put("version", "foo");
        hashMap.put("buildTime", "foo");
        hashMap.put("gitsha1", "foo");

        Assert.assertEquals(hashMap, moduleInfo.getAsMap());
    }

    @Test
    public void testHashCode1() {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        ModuleInfo moduleInfo = new ModuleInfo(moduleType, "classname");

        Assert.assertEquals(1248676478, moduleInfo.hashCode());
    }

    @Test
    public void testHashCode2() throws IOException {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        StreamInput streamInput = PowerMockito.mock(StreamInput.class);
        PowerMockito.when(streamInput.readString()).thenReturn("foo");
        PowerMockito.when(streamInput.readEnum(ModuleType.class))
                .thenReturn(moduleType);
        ModuleInfo moduleInfo = new ModuleInfo(streamInput);

        Assert.assertEquals(-793453215, moduleInfo.hashCode());
    }

    @Test
    public void testEquals1() {
        ModuleType moduleType1 =
                ModuleType.getByDefaultImplClass(String.class);
        ModuleType moduleType2 =
                ModuleType.getByDefaultImplClass(HTTPAuthenticator.class);
        ModuleInfo moduleInfo1 = new ModuleInfo(moduleType1, "foo");
        ModuleInfo moduleInfo2 = new ModuleInfo(moduleType2, "foo");
        ModuleInfo moduleInfo3 = new ModuleInfo(moduleType1, null);
        ModuleInfo moduleInfo4 = new ModuleInfo(moduleType1, "foo");

        Assert.assertTrue(moduleInfo1.equals(moduleInfo1));
        Assert.assertTrue(moduleInfo1.equals(moduleInfo4));

        Assert.assertFalse(moduleInfo1.equals(null));
        Assert.assertFalse(moduleInfo1.equals("foo"));
        Assert.assertFalse(moduleInfo3.equals(moduleInfo1));
        Assert.assertFalse(moduleInfo1.equals(moduleInfo3));
        Assert.assertFalse(moduleInfo1.equals(moduleInfo2));
    }

    @Test
    public void testEquals2() throws IOException {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        StreamInput streamInput = PowerMockito.mock(StreamInput.class);
        PowerMockito.when(streamInput.readString()).thenReturn("foo");
        PowerMockito.when(streamInput.readEnum(ModuleType.class))
                .thenReturn(moduleType);
        ModuleInfo moduleInfo = new ModuleInfo(moduleType, "foo");
        ModuleInfo moduleInfo2 = new ModuleInfo(streamInput);

        Assert.assertFalse(moduleInfo.equals(moduleInfo2));

        moduleInfo.setBuildTime(null);
        Assert.assertFalse(moduleInfo.equals(moduleInfo2));

        moduleInfo.setBuildTime("foo");
        Assert.assertFalse(moduleInfo.equals(moduleInfo2));

        moduleInfo.setVersion("foo");
        Assert.assertFalse(moduleInfo.equals(moduleInfo2));

        moduleInfo.setGitsha1(null);
        Assert.assertFalse(moduleInfo.equals(moduleInfo2));

        moduleInfo.setVersion(null);
        moduleInfo2.setVersion("bar");
        Assert.assertFalse(moduleInfo.equals(moduleInfo2));
    }

    @Test
    public void testToString1() {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        ModuleInfo moduleInfo = new ModuleInfo(moduleType, "classname");

        Assert.assertEquals(
                "Module [type=UNKNOWN, implementing class=classname]",
                moduleInfo.toString());
    }

    @Test
    public void testToString2() throws IOException {
        ModuleType moduleType = ModuleType.getByDefaultImplClass(String.class);
        StreamInput streamInput = PowerMockito.mock(StreamInput.class);
        PowerMockito.when(streamInput.readString()).thenReturn("foo");
        PowerMockito.when(streamInput.readEnum(ModuleType.class))
                .thenReturn(moduleType);
        ModuleInfo moduleInfo = new ModuleInfo(streamInput);

        Assert.assertEquals(
                "Module [type=UNKNOWN, implementing class=foo]",
                moduleInfo.toString());
    }
}
