/*
 * Copyright 2015-2018 _floragunn_ GmbH
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

package com.amazon.opendistroforelasticsearch.security.test.helper.rules;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class OpenDistroSecurityTestWatcher extends TestWatcher{
  
	@Override
  protected void starting(final Description description) {
      final String methodName = description.getMethodName();
      String className = description.getClassName();
      className = className.substring(className.lastIndexOf('.') + 1);
      System.out.println("---------------- Starting JUnit-test: " + className + " " + methodName + " ----------------");
  }

  @Override
  protected void failed(final Throwable e, final Description description) {
      final String methodName = description.getMethodName();
      String className = description.getClassName();
      className = className.substring(className.lastIndexOf('.') + 1);
      System.out.println(">>>> " + className + " " + methodName + " FAILED due to " + e);
  }

  @Override
  protected void finished(final Description description) {
      // System.out.println("-----------------------------------------------------------------------------------------");
  }

}
