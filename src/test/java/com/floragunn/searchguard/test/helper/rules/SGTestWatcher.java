/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.test.helper.rules;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class SGTestWatcher extends TestWatcher{
  
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
