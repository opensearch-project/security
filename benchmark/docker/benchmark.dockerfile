FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS linux_stage_0

ARG UID=1000
ARG GID=1000
ARG VERSION
ARG TEMP_DIR=/tmp/opensearch
ARG OPENSEARCH_HOME=/usr/share/opensearch
ARG OPENSEARCH_PATH_CONF=$OPENSEARCH_HOME/config
ARG SECURITY_PLUGIN_DIR=$OPENSEARCH_HOME/plugins/opensearch-security
ARG PERFORMANCE_ANALYZER_PLUGIN_CONFIG_DIR=$OPENSEARCH_PATH_CONF/opensearch-performance-analyzer

RUN dnf update --releasever=latest -y && dnf install -y tar gzip shadow-utils which wget && dnf clean all

RUN groupadd -g $GID opensearch && \
    adduser -u $UID -g $GID -d $OPENSEARCH_HOME opensearch && \
    mkdir $TEMP_DIR

COPY entrypoint.sh $OPENSEARCH_HOME/entrypoint.sh

RUN ls -l $TEMP_DIR && \
    wget https://artifacts.opensearch.org/snapshots/core/opensearch/${VERSION}-SNAPSHOT/opensearch-min-${VERSION}-SNAPSHOT-linux-x64-latest.tar.gz && \
    tar -xzpf opensearch-*.tar.gz -C $OPENSEARCH_HOME --strip-components=1 && \
    mkdir -p $OPENSEARCH_HOME/data && chown -Rv $UID:$GID $OPENSEARCH_HOME/data && \
    chmod +x $OPENSEARCH_HOME/entrypoint.sh && \
    ls -l $OPENSEARCH_HOME



FROM public.ecr.aws/amazonlinux/amazonlinux:2023

ARG UID=1000
ARG GID=1000
ARG OPENSEARCH_HOME=/usr/share/opensearch

RUN dnf update --releasever=latest -y && dnf install -y tar gzip shadow-utils which && dnf clean all

RUN groupadd -g $GID opensearch && \
    adduser -u $UID -g $GID -d $OPENSEARCH_HOME opensearch

COPY --from=linux_stage_0 --chown=$UID:$GID $OPENSEARCH_HOME $OPENSEARCH_HOME
WORKDIR $OPENSEARCH_HOME

RUN echo "export JAVA_HOME=$OPENSEARCH_HOME/jdk" >> /etc/profile.d/java_home.sh && \
    echo "export PATH=\$PATH:\$JAVA_HOME/bin" >> /etc/profile.d/java_home.sh && \
    ls -l $OPENSEARCH_HOME

ENV JAVA_HOME=$OPENSEARCH_HOME/jdk
ENV PATH=$PATH:$JAVA_HOME/bin:$OPENSEARCH_HOME/bin

COPY opensearch-security-*.zip $TEMP_DIR/opensearch-security.zip

USER $UID

RUN /bin/bash -c "yes | ./bin/opensearch-plugin install file:$TEMP_DIR/opensearch-security.zip"

EXPOSE 9200 9300

ENTRYPOINT ["./entrypoint.sh"]
CMD ["opensearch"]
