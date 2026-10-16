import html, os
HERE=os.path.dirname(os.path.abspath(__file__))
F='font-family="Arial, Helvetica, sans-serif"'
INK='#1F1F1F'; MUT='#595959'; LINE='#7A7A7A'; BOX='#F3F3F3'; RED='#C8102E'
def e(t): return html.escape(t)
class S:
    def __init__(s,w,h): s.w=w; s.h=h; s.o=[]
    def box(s,x,y,w,h,title,lines=(),fill=BOX,stroke=LINE,tc=INK,sw=1.2,tsz=14):
        s.o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')
        n=len(lines); ty=y+ (h-(tsz+4+ n*16))/2 + tsz-1 if True else y+20
        s.o.append(f'<text x="{x+w/2}" y="{ty}" text-anchor="middle" {F} font-size="{tsz}" font-weight="700" fill="{tc}">{e(title)}</text>')
        for i,l in enumerate(lines):
            s.o.append(f'<text x="{x+w/2}" y="{ty+6+16*(i+1)}" text-anchor="middle" {F} font-size="12.5" fill="{MUT if tc==INK else tc}">{e(l)}</text>')
    def txt(s,x,y,t,sz=12.5,anchor='start',fill=MUT,bold=False,italic=False):
        s.o.append(f'<text x="{x}" y="{y}" text-anchor="{anchor}" {F} font-size="{sz}" fill="{fill}"{" font-weight=\"700\"" if bold else ""}{" font-style=\"italic\"" if italic else ""}>{e(t)}</text>')
    def arrow(s,pts,color=LINE,dash=False,w=1.6):
        d='M'+' L'.join(f'{x},{y}' for x,y in pts)
        s.o.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{w}"{" stroke-dasharray=\"5 4\"" if dash else ""} marker-end="url(#ah)"/>')
    def lab(s,x,y,t,sz=11,anchor='middle',fill=MUT,w=None):
        w=w or (len(t)*sz*0.52+6); x0=x-w/2 if anchor=='middle' else (x if anchor=='start' else x-w)
        s.o.append(f'<rect x="{x0}" y="{y-sz}" width="{w}" height="{sz+4}" fill="#fff" opacity="0.95"/>')
        s.txt(x,y,t,sz,anchor,fill,False,True)
    def line(s,pts,color=LINE,w=1.6):
        s.o.append('<path d="M'+' L'.join(f'{x},{y}' for x,y in pts)+f'" fill="none" stroke="{color}" stroke-width="{w}"/>')
    def lane(s,x,y,w,h,label):
        s.o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#FAFAFA" stroke="#D9D9D9"/>')
        s.txt(x+w/2,y+16,label.upper(),11.5,'middle','#8A8A8A',True)
    def svg(s):
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{s.w}" height="{s.h}" viewBox="0 0 {s.w} {s.h}"><defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{LINE}"/></marker></defs><rect width="{s.w}" height="{s.h}" fill="#fff"/>'+''.join(s.o)+'</svg>'

# ---------------- Figure 1: from vehicle report to case
s=S(780,560)
s.lane(8,8,764,92,'Sources')
s.lane(8,116,764,150,'')
s.txt(764,132,'FLEET IDS SIEM · ANALYST PC · LOOPBACK ONLY',11.5,'end','#8A8A8A',True)
s.lane(8,282,764,130,'Analysis')
s.lane(8,428,764,124,'Access and accountability')
s.box(24,36,230,52,'Vehicle IDS reports',['CSV · XLSX · JSON file import'])
s.box(274,36,230,52,'CycurGUARD backend',['REST pull (manual or scheduled)'])
s.box(524,36,232,52,'Other sources',['POST /api/ingest (JSON)'])
# core
s.box(24,148,170,100,'Import',['column mapping','timestamp check','de-duplication','VIN upper-case'])
s.box(230,148,170,100,'SQLite database',['events · catalog','alerts · cases','users · audit log'],fill='#EEF3FD',stroke='#1F5FE0')
s.box(436,148,150,100,'Event catalog',['severity and','category per','event type'])
s.box(610,148,146,100,'VIN decoder',['market, year,','engine, body'])
s.arrow([(139,88),(109,148)]); s.arrow([(389,88),(160,148)]); s.arrow([(640,88),(180,148)])
s.arrow([(194,198),(230,198)])
s.arrow([(436,198),(400,198)]); s.arrow([(610,198),(586,198)])
# analysis
s.box(24,316,170,80,'Detection rules',['six rules, parameters','set by the administrator'])
s.box(230,316,150,80,'Alerts',['new · in progress ·','resolved · false positive','· suppressed'])
s.box(416,316,160,80,'Suppression rules',['reason and expiry,','events never hidden'],fill='#FFFFFF')
s.box(612,316,144,80,'Cases and report',['checklist · experts ·','notes · case report'])
s.arrow([(315,248),(315,282),(109,282),(109,316)])
s.arrow([(194,356),(230,356)]); s.arrow([(416,340),(380,340)]); s.arrow([(305,396),(305,405),(684,405),(684,396)])
# access
s.box(24,462,170,70,'Sign-in and roles',['viewer · analyst · admin','scrypt, lock-out, MFA'])
s.box(230,462,170,70,'Audit log',['every state change,','hash chain, verify'],fill='#FBE9EC',stroke=RED)
s.box(436,462,150,70,'API tokens',['view · modify · full','hash only stored'])
s.box(610,462,146,70,'MCP agent',['read + notes marked','[AI agent]'])
s.txt(390,550,'All requests: loopback Host check · X-SIEM header on writes · CSP and security headers',11.5,'middle',MUT,False,True)
open(os.path.join(HERE,'fig1.svg'),'w',encoding='utf8').write(s.svg())

# ---------------- Figure 2: worked example, burst rule
t=S(780,330)
t.txt(20,28,'Burst rule: 4 events of INVALID_SIG (medium) on one vehicle, window 60 min, threshold 3',14,'start',INK,True)
x0,x1=60,740; ax=150; scale=(x1-x0)/130.0   # 130 minutes across
def X(m): return x0+m*scale
t.o.append(f'<line x1="{x0}" y1="{ax}" x2="{x1}" y2="{ax}" stroke="{LINE}" stroke-width="2"/>')
for m in (0,30,60,90,120):
    t.o.append(f'<line x1="{X(m)}" y1="{ax-5}" x2="{X(m)}" y2="{ax+5}" stroke="{LINE}" stroke-width="1.5"/>'); t.txt(X(m),ax+22,f'{m} min',11.5,'middle',MUT)
t.o.append(f'<rect x="{X(0)}" y="{ax-62}" width="{X(45)-X(0)}" height="44" rx="6" fill="#FBE9EC" stroke="{RED}" stroke-width="1.6" stroke-dasharray="6 4"/>')
t.txt((X(0)+X(45))/2,ax-72,'cluster: 3 events within 45 min (≤ 60 min)',12.5,'middle',RED,True)
for i,(m,inside) in enumerate(((0,True),(20,True),(45,True),(120,False))):
    col=RED if inside else '#9A9A9A'
    t.o.append(f'<circle cx="{X(m)}" cy="{ax-40}" r="9" fill="{col}"/>'); t.txt(X(m),ax-36,str(i+1),11,'middle','#fff',True)
t.txt(X(120),ax-62,'outside the window',11.5,'middle',MUT,False,True)
t.box(60,215,300,86,'Result of the rule',['1 alert "3× INVALID_SIG within 45 min"','event 4 is not part of it'],fill='#F3F3F3')
t.box(400,215,340,86,'Severity',['catalog severity medium, raised by one level','→ alert severity high (capped at high)'],fill='#FBE9EC',stroke=RED,tc=RED)
open(os.path.join(HERE,'fig2.svg'),'w',encoding='utf8').write(t.svg())
