# legacy-app — the case-management application. Tomcat 8.5 on Java 8 (Temurin),
# HTTPS on 8443 only: TLS 1.2, an RSA-2048 certificate issued by the internal CA
# in a PKCS#12 keystore whose password is in server.xml, ECDHE-RSA suites only,
# the P-256 and P-384 curves pinned on the JVM command line.
FROM tomcat:8.5-jre8-temurin@sha256:e3ca75a4b11560bfb30894c3fa5d066ff0105e2e8e1ad183711df97606321e51
# No outbound TLS: the OS trust store and the JRE's cacerts are removed, so the
# image holds only the material the service itself uses.
RUN rm -rf /etc/ssl/certs /usr/share/ca-certificates "$JAVA_HOME/lib/security/cacerts" \
      /usr/local/tomcat/webapps/* /usr/local/tomcat/webapps.dist
COPY --from=pki /pki/legacy-app/keystore.p12 /usr/local/tomcat/conf/keystore.p12
COPY server.xml /usr/local/tomcat/conf/server.xml
COPY setenv.sh /usr/local/tomcat/bin/setenv.sh
EXPOSE 8443
