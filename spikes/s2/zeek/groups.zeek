# Log every TLS client's offered key-exchange groups (the supported_groups extension,
# which Zeek 9 still calls elliptic_curves).
@load base/protocols/ssl
module S2;
export {
  redef enum Log::ID += { LOG };
  type Info: record { ts: time &log; uid: string &log; server: addr &log; offered: vector of count &log; };
}
event zeek_init() { Log::create_stream(S2::LOG, [$columns=Info, $path="client_groups"]); }
event ssl_extension_elliptic_curves(c: connection, is_client: bool, curves: index_vec) {
  if ( is_client ) Log::write(S2::LOG, [$ts=network_time(), $uid=c$uid, $server=c$id$resp_h, $offered=curves]);
}
