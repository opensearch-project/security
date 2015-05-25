/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.config;

import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.common.bytes.BytesArray;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.tokeneval.MalformedConfigurationException;
import com.floragunn.searchguard.tokeneval.TokenEvaluator;
import com.floragunn.searchguard.tokeneval.TokenEvaluator.Evaluator;
import com.floragunn.searchguard.tokeneval.TokenEvaluator.FilterAction;
import com.google.common.collect.Lists;

public class EvaluatorTest {

    @Test
    public void testEval() throws IOException, MalformedConfigurationException {
        final TokenEvaluator te = new TokenEvaluator(new BytesArray(loadFile("ac_rules_6.json")));
        try {
            te.getEvaluator(Lists.<String> newArrayList(), Lists.<String> newArrayList(), Lists.<String> newArrayList(),
                    InetAddress.getLocalHost(), new User("test"));
            Assert.fail();
        } catch (final MalformedConfigurationException e) {
            //expected
            Assert.assertTrue(e.getMessage().contains("filters at all"));
        }

    }

    @Test
    public void testEval2() throws IOException, MalformedConfigurationException {
        final TokenEvaluator te = new TokenEvaluator(new BytesArray(loadFile("ac_rules_1.json")));

        Evaluator eval = te.getEvaluator(Lists.<String> newArrayList("public"), Lists.<String> newArrayList(),
                Lists.<String> newArrayList(), InetAddress.getLocalHost(), new User("test"));
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("XX", "XX"));

        try {
            eval = te.getEvaluator(Lists.<String> newArrayList("xxx"), Lists.<String> newArrayList("internal"),
                    Lists.<String> newArrayList(), InetAddress.getLocalHost(), new User("test"));
            Assert.fail();
        } catch (final MalformedConfigurationException e) {
            //expected
        }

        final User user = new User("jacksonm");
        user.addRole("ceo");

        eval = te.getEvaluator(Lists.<String> newArrayList("xxx"), Lists.<String> newArrayList("internal"), Lists.<String> newArrayList(),
                InetAddress.getLocalHost(), user);
        Assert.assertFalse(eval.getBypassAll());
        Assert.assertTrue(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.EXECUTE, eval.evaluateFilter("XX", "XX"));
    }

    //look
    @Test
    public void testEval3() throws IOException, MalformedConfigurationException {
        final TokenEvaluator te = new TokenEvaluator(new BytesArray(loadFile("ac_rules_4.json")));

        Evaluator eval = te.getEvaluator(Lists.<String> newArrayList("public"), Lists.<String> newArrayList(),
                Lists.<String> newArrayList(), InetAddress.getLocalHost(), new User("test"));
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("XX", "XX"));

        eval = te.getEvaluator(Lists.<String> newArrayList("eight"), Lists.<String> newArrayList(), Lists.<String> newArrayList(),
                InetAddress.getByName("8.8.8.8"), new User("test"));
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("XX", "XX"));

        eval = te.getEvaluator(Lists.<String> newArrayList(), Lists.<String> newArrayList("internal"), Lists.<String> newArrayList(),
                InetAddress.getByName("127.0.0.1"), new User("test"));
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("XX", "XX"));

        eval = te.getEvaluator(Lists.<String> newArrayList(), Lists.<String> newArrayList("internal"), Lists.<String> newArrayList("xxx"),
                InetAddress.getByName("8.8.8.8"), new User("test"));
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("check", "1"));
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("XX", "XX"));
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("read", "only"));

        final User user = new User("jacksonm");
        user.addRole("ceo");

        eval = te.getEvaluator(Lists.<String> newArrayList(), Lists.<String> newArrayList("internal"), Lists.<String> newArrayList("xxx"),
                InetAddress.getByName("8.8.8.8"), user);
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("check", "1"));
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("XX", "XX"));
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("read", "only"));
    }

    @Test
    public void testEval4() throws IOException, MalformedConfigurationException {
        final TokenEvaluator te = new TokenEvaluator(new BytesArray(loadFile("ac_rules_6.json")));

        final User user = new User("jacksonm");
        user.addRole("ceo");
        user.addRole("finance");

        final Evaluator eval = te.getEvaluator(Lists.<String> newArrayList("ceodata"), Lists.<String> newArrayList(),
                Lists.<String> newArrayList(), InetAddress.getByName("8.8.8.8"), user);
        Assert.assertTrue(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());

    }

    @Test
    public void testEval5() throws IOException, MalformedConfigurationException {
        final TokenEvaluator te = new TokenEvaluator(new BytesArray(loadFile("ac_rules_6.json")));

        final User user = new User("jacksonm");
        user.addRole("finance");

        final Evaluator eval = te.getEvaluator(Lists.<String> newArrayList("ceodata"), Lists.<String> newArrayList(),
                Lists.<String> newArrayList(), InetAddress.getByName("8.8.8.8"), user);
        Assert.assertFalse(eval.getBypassAll());
        Assert.assertFalse(eval.getExecuteAll());
        Assert.assertEquals(FilterAction.EXECUTE, eval.evaluateFilter("dlsfilter", "filter_sensitive_from_ceodata"));
        Assert.assertEquals(FilterAction.EXECUTE, eval.evaluateFilter("actionrequestfilter", "readonly"));
        Assert.assertEquals(FilterAction.BYPASS, eval.evaluateFilter("xxx", "xxx"));
    }

    protected final String loadFile(final String file) throws IOException {

        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
        return sw.toString();

    }

}
