- [Developer Guide](#developer-guide)
    - [Forking and Cloning](#forking-and-cloning)
    - [Install Prerequisites](#install-prerequisites)
        - [JDK 14](#jdk-14)
    - [Building](#building)
    - [Using IntelliJ IDEA](#using-intellij-idea)
    - [Submitting Changes](#submitting-changes)

## Developer Guide

So you want to contribute code to this project? Excellent! We're glad you're here. Here's what you need to do.

### Forking and Cloning

Fork this repository on GitHub, and clone locally with `git clone`.

### Install Prerequisites

#### JDK 14

OpenSearch components build using Java 14 at a minimum. This means you must have a JDK 14 installed with the environment variable `JAVA_HOME` referencing the path to Java home for your JDK 14 installation, e.g. `JAVA_HOME=/usr/lib/jvm/jdk-14`.

### Building

To build from the command line,

```
mvn clean package -Padvanced -DskipTests
```

### Using IntelliJ IDEA

Launch Intellij IDEA, choose **Import Project**, and select the `pom.xml` file in the root of this package.

### Submitting Changes

See [CONTRIBUTING](CONTRIBUTING.md).