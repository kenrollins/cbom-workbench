# legacy-app: the JVM's TLS named groups are pinned here, so the curves the
# listener offers are a line in the repository, not a runtime default.
CATALINA_OPTS="$CATALINA_OPTS -Xmx96m -Djdk.tls.namedGroups=secp256r1,secp384r1"
