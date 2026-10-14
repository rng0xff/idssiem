"""Security regression test. Usage: start the app with a fresh database (IDS_SIEM_DB=/tmp/x/data/t.db python3 idssiem.py --port 8851), then
   python3 tools/security_test.py 8851 /tmp/x/data/t.db   (takes about a minute: it waits out the sign-in flood limit)"""
import json, sys, socket, os, stat, sqlite3, hashlib, urllib.request, urllib.error
PORT=int(sys.argv[1]); DB=sys.argv[2]; B=f"http://localhost:{PORT}"
ok=bad=0
def chk(n,c,x=""):
    global ok,bad
    if c: ok+=1; print("PASS",n)
    else: bad+=1; print("FAIL",n,x)
def raw(req):
    s=socket.create_connection(("127.0.0.1",PORT),timeout=10); s.sendall(req.encode()); data=b""
    try:
        while True:
            d=s.recv(65536)
            if not d: break
            data+=d
            if b"\r\n\r\n" in data and (b"Content-Length" in data): 
                head,_,body=data.partition(b"\r\n\r\n")
                n=int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0].split(b":")[1])
                if len(body)>=n: break
    except Exception: pass
    s.close(); return data.decode("latin1")
def call(m,p,body=None,cookie=None):
    h={"X-SIEM":"1"}
    if cookie: h["Cookie"]="siem_session="+cookie
    d=json.dumps(body).encode() if body is not None else None
    if d: h["Content-Type"]="application/json"
    try:
        r=urllib.request.urlopen(urllib.request.Request(B+p,data=d,method=m,headers=h)); return r.status,r.read(),dict(r.headers),r
    except urllib.error.HTTPError as e: return e.code,e.read(),dict(e.headers),e
# headers
s,b,h,_=call("GET","/"); 
for k in ("X-Frame-Options","Referrer-Policy","Cross-Origin-Opener-Policy","Permissions-Policy"): chk("header "+k,k in h,h)
csp=h.get("Content-Security-Policy","")
for d in ("frame-ancestors 'none'","base-uri 'none'","object-src 'none'","form-action 'self'"): chk("CSP "+d,d in csp,csp)
# host header
for host,exp in (("localhost:%d"%PORT,200),("127.0.0.1",200),("[::1]:%d"%PORT,200),("evil.com",403),("[evil.com]",403),("localhost.evil.com",403),("localhost:80@evil.com",403),("127.0.0.1.evil.com",403)):
    r=raw(f"GET /api/auth/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    chk(f"host {host!r} -> {exp}",r.startswith(f"HTTP/1.1 {exp}") or r.startswith(f"HTTP/1.0 {exp}"),r[:40])
# bad content-length
r=raw(f"POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nX-SIEM: 1\r\nContent-Length: abc\r\nConnection: close\r\n\r\n")
chk("non-numeric Content-Length -> 400",r.startswith("HTTP/1.1 400"),r[:60])
r=raw(f"POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nX-SIEM: 1\r\nContent-Length: -5\r\nConnection: close\r\n\r\n")
chk("negative Content-Length -> 400",r.startswith("HTTP/1.1 400"),r[:60])
big=20*1024*1024
r=raw(f"POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nX-SIEM: 1\r\nContent-Type: application/json\r\nContent-Length: {big}\r\nConnection: close\r\n\r\n")
chk("20 MB JSON body refused (413)",r.startswith("HTTP/1.1 413"),r[:60])
# setup + login, 500 hides internals
s,b,_,_=call("POST","/api/auth/setup",{"username":"root","password":"correct horse battery"}); chk("setup",s==200,b)
s,b,h,_=call("POST","/api/auth/login",{"username":"root","password":"correct horse battery"}); ck=h["Set-Cookie"].split(";")[0].split("=")[1]
chk("login",s==200)
con=sqlite3.connect(DB); pw=con.execute("select pw_hash from users").fetchone()[0]
chk("new hashes use scrypt N=32768",pw.split("$")[1]=="32768",pw[:20])
# legacy hash upgrade
salt=os.urandom(16); old=hashlib.scrypt(b"correct horse battery",salt=salt,n=2**14,r=8,p=1,dklen=32)
con.execute("update users set pw_hash=?",(f"scrypt$16384$8$1${salt.hex()}${old.hex()}",)); con.commit()
s,b,h,_=call("POST","/api/auth/login",{"username":"root","password":"correct horse battery"}); chk("legacy hash still verifies",s==200,b)
pw=sqlite3.connect(DB).execute("select pw_hash from users").fetchone()[0]; chk("legacy hash upgraded at sign-in",pw.split("$")[1]=="32768",pw[:20])
# CSV formula injection
con=sqlite3.connect(DB)
call("POST","/api/ingest",{"events":[{"report.event_type":"sev","sev_metadata.timestamp":1790000000000,"vin":"SC6GM1AA0RF000001","ecu_name":"ETGW","sev_metadata.event_id":1,"sev_metadata.name":"=HYPERLINK(\"http://x\")","sev_metadata.description":"+cmd|' /C calc'!A0"}]},cookie=ck)
s,b,h,_=call("GET","/api/export.csv",cookie=ck); t=b.decode("utf-8-sig")
chk("event export neutralises =formula",'"\'=HYPERLINK' in t or "'=HYPERLINK" in t,t[:300]); chk("event export neutralises +formula","'+cmd" in t,t[:300])
chk("no raw formula cell",";=HYPERLINK" not in t and ";+cmd" not in t)
# DB perms
for f in (DB,DB+"-wal"):
    if os.path.exists(f): chk("perm 600 "+os.path.basename(f),stat.S_IMODE(os.stat(f).st_mode)==0o600,oct(os.stat(f).st_mode))
chk("data dir 700 or private",stat.S_IMODE(os.stat(os.path.dirname(DB)).st_mode)&0o077==0,oct(os.stat(os.path.dirname(DB)).st_mode))
# throttle: 40 failed sign-ins, then 429 even for the right password
codes=[]
for i in range(45):
    s,b,_,_=call("POST","/api/auth/login",{"username":f"nobody{i}","password":"x"}); codes.append(s)
chk("failed sign-ins answered 401 first",codes[0]==401,codes[:3]); chk("flood is throttled with 429",429 in codes,codes)
s,b,_,_=call("POST","/api/auth/login",{"username":"root","password":"correct horse battery"}); chk("even correct password waits during a flood",s==429,s)
s,b,_,_=call("GET","/api/summary",cookie=ck); chk("existing session still works during the flood",s==200,s)
print(f"\n{ok}/{ok+bad} passed"); sys.exit(1 if bad else 0)
