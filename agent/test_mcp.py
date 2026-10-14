"""Checks the MCP server against a running app that holds data (edit B, the login and the case number below for your setup)."""
import json, subprocess, sys, os, urllib.request
B="http://localhost:8860"
def api(m,p,body=None,ck=None):
    h={"X-SIEM":"1","Content-Type":"application/json"}
    if ck: h["Cookie"]="siem_session="+ck
    r=urllib.request.urlopen(urllib.request.Request(B+p,data=json.dumps(body).encode() if body is not None else None,method=m,headers=h)); return json.loads(r.read()),r.headers
_,h=api("POST","/api/auth/login",{"username":"root","password":"correct horse battery"}); ck=h["Set-Cookie"].split(";")[0].split("=")[1]
view,_=api("POST","/api/tokens",{"name":"agent-view","perm":"view","expires_days":1},ck=ck)
mod,_=api("POST","/api/tokens",{"name":"agent-modify","perm":"modify","expires_days":1},ck=ck)
ok=bad=0
def chk(n,c,x=""):
    global ok,bad
    if c: ok+=1; print("PASS",n)
    else: bad+=1; print("FAIL",n,str(x)[:300])
class Cli:
    def __init__(s,tok):
        env=dict(os.environ,IDS_SIEM_URL=B,IDS_SIEM_TOKEN=tok)
        s.p=subprocess.Popen([sys.executable,os.path.join(os.path.dirname(os.path.abspath(__file__)),"mcp_server.py")],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env); s.i=0
    def rpc(s,method,params=None,notify=False):
        s.i+=1; m={"jsonrpc":"2.0","method":method,"params":params or {}}
        if not notify: m["id"]=s.i
        s.p.stdin.write(json.dumps(m)+"\n"); s.p.stdin.flush()
        if notify: return None
        return json.loads(s.p.stdout.readline())
    def tool(s,name,**a):
        r=s.rpc("tools/call",{"name":name,"arguments":a})["result"]; t=r["content"][0]["text"]
        return r["isError"], t
v=Cli(view["token"])
r=v.rpc("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}})["result"]
chk("initialize returns instructions",bool(r["instructions"]) and r["serverInfo"]["name"]=="fleet-ids")
v.rpc("notifications/initialized",notify=True)
tl=v.rpc("tools/list")["result"]["tools"]; chk("11 tools listed",len(tl)==11,len(tl)); chk("read tools flagged read-only",all(t["annotations"]["readOnlyHint"] for t in tl if not t["name"].startswith("add_")))
chk("no status/link/delete tool exists",not any(w in t["name"] for t in tl for w in ("status","link","close","delete","create","settings")))
e,t=v.tool("fleet_summary"); chk("fleet_summary",not e and json.loads(t)["total"]>0,t)
e,t=v.tool("list_alerts",size=5); al=json.loads(t); chk("list_alerts",not e and len(al["alerts"])==5,t)
aid=al["alerts"][0]["id"]
e,t=v.tool("get_alert",alert_id=aid); chk("get_alert has rule description",not e and "rule_description" in json.loads(t),t)
e,t=v.tool("alert_events",alert_id=aid,size=3); ae=json.loads(t); chk("alert_events returns events",not e and len(ae["events"])>0 and ae["filter_used"],t)
eid=ae["events"][0]["id"]
e,t=v.tool("get_event",event_id=eid); chk("get_event has backend details",not e and "backend" in json.loads(t),t[:200])
e,t=v.tool("search_events",query="ecu:ETGW",size=3); chk("search_events",not e and len(json.loads(t)["events"])==3,t[:200])
vin=ae["events"][0]["vin"]; e,t=v.tool("get_vehicle",vin=vin); chk("get_vehicle",not e,t[:200])
e,t=v.tool("list_cases"); chk("list_cases",not e,t[:200])
e,t=v.tool("get_case",case_id=1); chk("get_case",not e and json.loads(t)["id"]==1,t[:200])
e,t=v.tool("add_alert_note",alert_id=aid,note="Proposal: test note from a view token"); chk("view token cannot write notes (clear error)",e and "403" in t,t)
e,t=v.tool("get_alert",alert_id=999999); chk("missing alert -> tool error, not crash",e and "404" in t,t)
e,t=v.tool("nonsense"); chk("unknown tool -> error",e,t)
e,t=v.tool("get_alert",alert_id="abc"); chk("bad argument -> error",e,t)
chk("unknown method -> JSON-RPC error","error" in v.rpc("bogus"))
m=Cli(mod["token"]); m.rpc("initialize",{"protocolVersion":"2025-06-18"})
e,t=m.tool("add_alert_note",alert_id=aid,note="Proposal: likely false positive. Evidence: test."); chk("modify token writes note",not e,t)
a=api("GET",f"/api/alerts/{aid}",ck=ck)[0]; last=a["comments"][-1]
chk("note carries [AI agent] prefix",last["body"].startswith("[AI agent] "),last); chk("author shows API token",("API token #" in last["author"]),last)
chk("alert status unchanged",a["status"]==al["alerts"][0]["status"],a["status"])
e,t=m.tool("add_case_note",case_id=1,note="Looks related to the earlier bursts on this vehicle."); chk("case note",not e,t)
e,t=m.tool("add_alert_note",alert_id=aid,note="x"); chk("empty/short note refused",e,t)
au,_=api("GET","/api/audit?size=5",ck=ck); chk("audit entry via token",any(r["via"].startswith("token #") and r["action"] in ("alert.comment","case.comment") for r in au["rows"]),au["rows"][:3])
# prompt injection stays data: an event name containing instructions is returned inside JSON as a string
n=Cli("bad-token"); n.rpc("initialize",{}); e,t=n.tool("fleet_summary"); chk("bad token -> clear error",e and "401" in t,t)
print(f"\n{ok}/{ok+bad} passed"); sys.exit(1 if bad else 0)
