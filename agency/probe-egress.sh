#!/bin/sh
# Probe, from inside each slice container, that the internal bridge has no
# route out. Touches nothing beyond the container's own stack: with no route,
# no packet leaves it. Also checks, on the host, that the host holds no address
# on the slice bridge.
#
#   agency/probe-egress.sh            # every running service of the slice
#
# For each container: the routing table has no default route; a TCP connect to
# 192.0.2.1:443 (TEST-NET-1, RFC 5737, never routed) fails with "network
# unreachable"; so does a TCP connect to the lab inference gateway; a DNS
# lookup gets no answer. Exit 0 only if every probe fails that way: a missing
# tool or a timeout does not count as proof.
set -u
GATEWAY=${PQCH_PROBE_GATEWAY:?set PQCH_PROBE_GATEWAY to the inference gateway host:port}
fail=0
for c in $(docker compose -f "$(dirname "$0")/compose.yaml" ps -q); do
  name=$(docker inspect -f '{{.Name}}' "$c" | tr -d /)
  out=$(docker exec -i "$c" sh -s "$GATEWAY" <<'PROBE'
gw_host=${1%:*}; gw_port=${1#*:}
tcp() {  # host port -> "ok" or the connect error, verbatim
  if command -v bash >/dev/null 2>&1; then
    bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1 && echo ok
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 3 -O /dev/null "http://$1:$2/" 2>&1 && echo ok
  else
    echo "no tool to attempt a connection"
  fi | tr '\n' ' '
}
routes=$( (ip route 2>/dev/null || route -n 2>/dev/null || cat /proc/net/route) | tr '\n' ';')
echo "routes: $routes"
case "$routes" in *default*|*0.0.0.0\ \ \ \ \ \ *UG*) echo "RESULT default-route present";; *) echo "RESULT no-default-route";; esac
echo "testnet: $(tcp 192.0.2.1 443)"
echo "gateway: $(tcp "$gw_host" "$gw_port")"
if command -v nslookup >/dev/null 2>&1; then d=$(timeout 5 nslookup example.com 2>&1 | tail -2 | tr '\n' ' ')
else d=$(timeout 5 getent hosts example.com 2>&1 || echo "no answer"); fi
echo "dns: ${d:-no answer}"
PROBE
)
  echo "== $name"; echo "$out" | sed 's/^/   /'
  echo "$out" | grep -q 'RESULT no-default-route' || fail=1
  # Pass only on an explicit "unreachable": a missing tool or a timeout is not proof.
  for probe in testnet gateway; do
    echo "$out" | grep -E "^$probe: " | grep -qi 'unreachable' || fail=1
  done
  echo "$out" | grep -qE '^dns: .*(Address: [0-9]|^[0-9])' && fail=1
done
# The host itself: with an address on the bridge, everything it binds to
# 0.0.0.0 is reachable from the slice even though nothing is routed.
net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$c")
subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$net")
held=$(ip -o -4 addr show | awk '{print $4}' | grep -F "${subnet%.*}." || true)
echo "== host on $net ($subnet): host addresses '${held}'"
if [ -n "$held" ]; then echo "   the host holds an address on the slice bridge"; fail=1; fi
[ $fail -eq 0 ] && echo "PASS: no route out of the slice" || echo "FAIL: a slice container can reach out"
exit $fail
