# Wire posture from passive capture. For every TLS handshake: what the client offered (key-exchange
# groups, key shares, signature algorithms, versions) and what the server chose; for SSH, Zeek's own
# ssh.log already carries the negotiated key exchange and host key. Written as JSON beside Zeek's
# base logs. Nothing here reads payloads; a handshake is the only thing examined.
@load base/protocols/ssl
@load base/protocols/ssh
@load base/files/x509
# The 802.1Q tag on every connection (conn.log `vlan`, `inner_vlan`), joined to posture by uid;
# and how much of the mirror was dropped before Zeek saw it (capture_loss.log, every 15 minutes).
@load policy/protocols/conn/vlan-logging
@load policy/misc/capture-loss

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1hr;

module Posture;
export {
  redef enum Log::ID += { LOG };
  type Info: record {
    ts: time &log;
    uid: string &log;
    client: addr &log;
    server: addr &log;
    server_port: port &log;
    sni: string &log &optional;
    offered_groups: vector of count &log &optional;      # client supported_groups
    client_key_shares: vector of count &log &optional;   # TLS 1.3 key_share groups the client sent
    server_key_share: count &log &optional;              # TLS 1.3: the group the server chose
    server_ecdh_curve: count &log &optional;             # TLS 1.2: the curve in ServerKeyExchange
    client_sig_algs: vector of count &log &optional;     # client signature_algorithms (sig<<8 | hash, or TLS 1.3 scheme)
    client_versions: vector of count &log &optional;     # client supported_versions
    version: string &log &optional;                      # as negotiated, from ssl.log's view
    cipher: string &log &optional;
    established: bool &log &default=F;
  };
  global written: set[string];
}

global pending: table[string] of Info;

function rec(c: connection): Info {
  if ( c$uid !in pending )
    pending[c$uid] = [$ts=network_time(), $uid=c$uid, $client=c$id$orig_h, $server=c$id$resp_h, $server_port=c$id$resp_p];
  return pending[c$uid];
}
function flush(c: connection) {
  if ( c$uid in pending && c$uid !in written ) {
    local r = pending[c$uid];
    if ( c?$ssl ) {
      if ( c$ssl?$version ) r$version = c$ssl$version;
      if ( c$ssl?$cipher ) r$cipher = c$ssl$cipher;
      if ( c$ssl?$server_name ) r$sni = c$ssl$server_name;
    }
    Log::write(Posture::LOG, r);
    add written[c$uid];
    delete pending[c$uid];
  }
}

event zeek_init() { Log::create_stream(Posture::LOG, [$columns=Info, $path="posture"]); }
# Only the handshake logs are kept. Everything else Zeek would write about a real estate (names
# looked up, URLs fetched, mail, files) is not evidence for this inventory and is not written.
event zeek_init() &priority=-10 {
  local keep: set[Log::ID] = { Conn::LOG, SSL::LOG, SSH::LOG, X509::LOG, Posture::LOG, PacketFilter::LOG, CaptureLoss::LOG };
  local drop: vector of Log::ID = vector();
  for ( id in Log::active_streams )
    if ( id !in keep ) drop += id;
  for ( i in drop ) Log::disable_stream(drop[i]);
}
event ssl_extension_elliptic_curves(c: connection, is_client: bool, curves: index_vec) {
  if ( is_client ) { local r = rec(c); r$offered_groups = curves; pending[c$uid] = r; }
}
event ssl_extension_key_share(c: connection, is_client: bool, curves: index_vec) {
  local r2 = rec(c);
  if ( is_client ) r2$client_key_shares = curves;
  else if ( |curves| > 0 ) r2$server_key_share = curves[0];
  pending[c$uid] = r2;
}
event ssl_ecdh_server_params(c: connection, curve: count, point: string) {
  local r3 = rec(c); r3$server_ecdh_curve = curve; pending[c$uid] = r3;
}
event ssl_extension_signature_algorithm(c: connection, is_client: bool, signature_algorithms: signature_and_hashalgorithm_vec) {
  if ( ! is_client ) return;
  local r4 = rec(c); local v: vector of count = vector();
  for ( i in signature_algorithms )
    v += signature_algorithms[i]$HashAlgorithm * 256 + signature_algorithms[i]$SignatureAlgorithm;
  r4$client_sig_algs = v; pending[c$uid] = r4;
}
event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec) {
  if ( is_client ) { local r5 = rec(c); r5$client_versions = versions; pending[c$uid] = r5; }
}
event ssl_established(c: connection) {
  if ( c$uid in pending ) { pending[c$uid]$established = T; }
  flush(c);
}
event connection_state_remove(c: connection) { flush(c); }
