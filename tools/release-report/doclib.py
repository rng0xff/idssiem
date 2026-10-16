import re, os, shutil, subprocess, zipfile, html, struct, tempfile
HERE=os.path.dirname(os.path.abspath(__file__))
TEMPLATE=os.path.join(HERE,'template.docx')   # INEOS work-instruction template (header, footer, styles, cover / TOC frame)
TPL=None                                       # set by make_pkg: directory with the unzipped template
def png_size(path):
    with open(path,'rb') as f: h=f.read(24)
    return struct.unpack('>II',h[16:24])
def esc(s): return html.escape(s,quote=False)
RPR_BASE=''
def runs(text, base_rpr=''):
    """inline markup: **bold**, `mono`, _italic_ (only with surrounding spaces/start)"""
    out=[]; pos=0
    for m in re.finditer(r'\*\*(.+?)\*\*|`(.+?)`|(?<![\w])_(.+?)_(?![\w])',text):
        if m.start()>pos: out.append(r_(text[pos:m.start()],base_rpr))
        if m.group(1) is not None: out.append(r_(m.group(1),base_rpr+'<w:b/><w:bCs/>'))
        elif m.group(2) is not None: out.append(r_(m.group(2),base_rpr+'<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="19"/><w:szCs w:val="19"/>'))
        else: out.append(r_(m.group(3),base_rpr+'<w:i/><w:iCs/>'))
        pos=m.end()
    if pos<len(text): out.append(r_(text[pos:],base_rpr))
    return ''.join(out)
def r_(t,rpr=''):
    return '<w:r>'+('<w:rPr>'+rpr+'</w:rPr>' if rpr else '')+'<w:t xml:space="preserve">'+esc(t)+'</w:t></w:r>'
IND='<w:ind w:left="-397" w:right="-680"/>'
class Doc:
    def __init__(s, title, docno, rev, outname, mediadir=None):
        s.mediadir=mediadir or tempfile.mkdtemp(prefix='tm-media-'); s.body=[]; s.heads=[]; s.bm=100; s.title=title; s.docno=docno; s.rev=rev; s.out=outname
        s.imgs=[]; s.nums=[]; s.fig=0; s.numid=200
    # --- paragraphs
    def p(s,text,keep=False,after=100,extra=''):
        s.body.append('<w:p><w:pPr>'+('<w:keepNext/>' if keep else '')+'<w:spacing w:after="%d" w:line="276" w:lineRule="auto"/>'%after+IND+extra+'</w:pPr>'+runs(text)+'</w:p>')
    def h(s,level,text):
        s.bm+=1; name='_Toc9%06d'%s.bm
        s.heads.append((level,text,name))
        s.body.append('<w:p><w:pPr><w:pStyle w:val="berschrift'+str(level)+'"/>'+('<w:ind w:left="63" w:hanging="687"/>' if level==2 else '')+'</w:pPr><w:bookmarkStart w:id="'+str(s.bm)+'" w:name="'+name+'"/>'+r_(text)+'<w:bookmarkEnd w:id="'+str(s.bm)+'"/></w:p>')
    def bullets(s,items,level=0):
        for it in items: s.body.append('<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="90"/></w:numPr><w:spacing w:after="60" w:line="276" w:lineRule="auto"/><w:ind w:left="%d" w:right="-680" w:hanging="360"/></w:pPr>'%(-37+level*360)+runs(it)+'</w:p>')
        s.spacer()
    def steps(s,items):
        s.numid+=1; s.nums.append(s.numid)
        for it in items: s.body.append('<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="%d"/></w:numPr><w:spacing w:after="60" w:line="276" w:lineRule="auto"/><w:ind w:left="-37" w:right="-680" w:hanging="360"/></w:pPr>'%s.numid+runs(it)+'</w:p>')
        s.spacer()
    def spacer(s): s.body.append('<w:p><w:pPr><w:spacing w:after="0" w:line="120" w:lineRule="exact"/></w:pPr></w:p>')
    def note(s,kind,text):
        col={'Note':'1F5FE0','Tip':'1A7F37','Warning':'D12C1F'}[kind]
        s.body.append('<w:p><w:pPr><w:keepLines/><w:pBdr><w:left w:val="single" w:sz="24" w:space="8" w:color="%s"/></w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="F3F3F3"/><w:spacing w:before="60" w:after="120" w:line="276" w:lineRule="auto"/><w:ind w:left="-200" w:right="-680"/></w:pPr>'%col+runs('**%s:** '%kind+text)+'</w:p>')
    def example(s,label,text): s.p('**%s** %s'%(label,text))
    # --- tables
    def table(s,widths,rows,header=True,small=True,bold_first=False):
        tot=sum(widths); sz=19 if small else 22
        x='<w:tbl><w:tblPr><w:tblStyle w:val="Tabellenraster"/><w:tblW w:w="%d" w:type="dxa"/><w:tblInd w:w="-431" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="1" w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr><w:tblGrid>'%tot+''.join('<w:gridCol w:w="%d"/>'%w for w in widths)+'</w:tblGrid>'
        for ri,row in enumerate(rows):
            hd=header and ri==0
            x+='<w:tr>'+('<w:trPr><w:cantSplit/>'+('<w:tblHeader/>' if hd else '')+'</w:trPr>')
            for ci,cell in enumerate(row):
                shd='<w:shd w:val="clear" w:color="auto" w:fill="E8E8E8"/>' if hd else ''
                paras=cell if isinstance(cell,list) else [cell]
                ps=''
                for t in paras:
                    rp='<w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/><w:sz w:val="%d"/><w:szCs w:val="%d"/>'%(sz,sz)+('<w:b/><w:bCs/>' if (hd or (bold_first and ci==0)) else '')
                    ps+='<w:p><w:pPr><w:spacing w:before="20" w:after="20" w:line="259" w:lineRule="auto"/></w:pPr>'+runs(t,rp)+'</w:p>'
                x+='<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/>%s</w:tcPr>%s</w:tc>'%(widths[ci],shd,ps)
            x+='</w:tr>'
        x+='</w:tbl>'; s.body.append(x); s.spacer()
    # --- images
    def img(s,path,caption,width_in=5.7):
        wpx,hpx=png_size(path)
        s.fig+=1; name='fig%02d.png'%s.fig; os.makedirs(s.mediadir,exist_ok=True)
        shutil.copy(path,os.path.join(s.mediadir,name))
        rid='rIdImg%d'%s.fig; s.imgs.append((rid,name))
        w=int(width_in*914400); hgt=int(w*hpx/wpx)
        d=('<w:p><w:pPr><w:keepNext/><w:spacing w:before="60" w:after="40"/><w:jc w:val="center"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="Figure %d"/><wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
           '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="%d" name="%s"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="%s"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:ln w="6350"><a:solidFill><a:srgbClr val="BFBFBF"/></a:solidFill></a:ln></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')%(w,hgt,300+s.fig,s.fig,300+s.fig,name,rid,w,hgt)
        s.body.append(d)
        s.body.append('<w:p><w:pPr><w:spacing w:after="160"/><w:jc w:val="center"/></w:pPr>'+r_('Figure %d: %s'%(s.fig,caption),'<w:i/><w:iCs/><w:sz w:val="18"/><w:szCs w:val="18"/><w:color w:val="595959"/>')+'</w:p>')
    def pagebreak(s): s.body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
    # --- TOC
    def toc(s,pages):
        x=[]
        for i,(lv,text,name) in enumerate(s.heads):
            n=s.numbers[i]; pg=pages.get(name,'')
            begin=('<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r>' if i==0 else '')
            x.append('<w:p><w:pPr><w:pStyle w:val="Verzeichnis%d"/></w:pPr>'%lv+begin+'<w:hyperlink w:anchor="%s" w:history="1"><w:r><w:rPr><w:rStyle w:val="Hyperlink"/><w:noProof/></w:rPr><w:t>%s</w:t></w:r><w:r><w:rPr><w:noProof/></w:rPr><w:tab/></w:r><w:r><w:rPr><w:rStyle w:val="Hyperlink"/><w:noProof/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r><w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:tab/></w:r><w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:instrText xml:space="preserve"> PAGEREF %s \\h </w:instrText></w:r><w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:t>%s</w:t></w:r><w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:hyperlink></w:p>'%(name,n,esc(text),name,pg))
        x.append('<w:p><w:pPr><w:pStyle w:val="Verzeichnis1"/></w:pPr><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
        return ''.join(x)
    def compute_numbers(s):
        c=[0,0,0]; s.numbers=[]
        for lv,_,_ in s.heads:
            c[lv-1]+=1
            for j in range(lv,3): c[j]=0
            s.numbers.append('.'.join(str(c[k]) for k in range(lv)))
    # --- assemble
    def build(s,pages,revrows):
        s.compute_numbers()
        d=open(os.path.join(TPL,'word','document.xml'),encoding='utf8').read()
        head=d[:d.index('<w:body>')+8]
        sdt0=d.index('<w:sdt>'); firstEntry=d.index('<w:p ',d.index('Inhaltsverzeichnisberschrift',d.index('CONTENT')-400)+10)
        # prefix: sdt start .. end of the CONTENT paragraph
        cont_end=d.index('</w:p>',d.index('>CONTENT<'))+6
        prefix=d[sdt0:cont_end]
        sect=d[d.rindex('<w:sectPr'):]
        # revision table: reuse template table, replace rows
        body=''.join(s.body)
        x=head+prefix+s.toc(pages)+'</w:sdtContent></w:sdt><w:p><w:r><w:br w:type="page"/></w:r></w:p>'+body+sect
        return x
def make_pkg(doc, pages, outpath, props):
    """props: author (core properties), footer_name (static file name shown in the footer)"""
    global TPL
    work=tempfile.mkdtemp(prefix='tm-work-'); TPL=os.path.join(work,'_tpl')
    with zipfile.ZipFile(TEMPLATE) as z: z.extractall(TPL)
    shutil.rmtree(TPL+'/[trash]',ignore_errors=True)
    xml=doc.build(pages,None)
    shutil.rmtree(work+'/pkg',ignore_errors=True); shutil.copytree(TPL,work+'/pkg'); pkg=work+'/pkg'
    os.makedirs(pkg+'/word/media',exist_ok=True)
    for a_,b_ in doc.imgs: shutil.copy(os.path.join(doc.mediadir,b_), pkg+'/word/media/'+b_)
    open(pkg+'/word/document.xml','w',encoding='utf8').write(xml)
    # header
    hp=pkg+'/word/header1.xml'; h=open(hp,encoding='utf8').read()
    def rep(h,old_seq,new):
        # replace the first w:t whose text == old_seq[0] ... simpler: set texts by position
        return h
    ts=re.findall(r'<w:t[^>]*>[^<]*</w:t>',h)
    texts=[re.sub(r'<[^>]+>','',t) for t in ts]
    # indices
    def idx(txt,start=0):
        for i in range(start,len(texts)):
            if texts[i]==txt: return i
        raise Exception(txt)
    i0=idx('Template '); 
    newts={}
    newts[i0]=doc.title
    for t in ['Work ','Instruction','_','EN']:
        newts[idx(t,i0)]=''
    j=idx('C',i0); newts[j]=doc.docno; 
    for t in ['ORP','-M2-QM-00','31']: newts[idx(t,j)]=''
    k=idx('Revision: 00'); newts[k]='Revision: '+doc.rev[:-1]; newts[idx('3',k)]=doc.rev[-1]
    out=h; pos=0; res=[]
    for i,t in enumerate(ts):
        a=out.index(t,pos)
        if i in newts:
            nt='<w:t xml:space="preserve">'+esc(newts[i])+'</w:t>'
            res.append(out[pos:a]+nt)
        else: res.append(out[pos:a]+t)
        pos=a+len(t)
    res.append(out[pos:]); open(hp,'w',encoding='utf8').write(''.join(res))
    fp=pkg+'/word/footer1.xml'; f=open(fp,encoding='utf8').read()
    # the FILENAME field is replaced by static text (the field result shows wrongly rendered dashes in some viewers)
    k=f.find(' FILENAME')
    if k<0: raise Exception('FILENAME field not found in footer')
    begin=f.rfind('<w:fldChar w:fldCharType="begin"/>',0,k); r0=f.rfind('<w:r',0,begin)
    while f[r0:r0+5] in ('<w:rP','<w:rF','<w:rS','<w:rs'): r0=f.rfind('<w:r ',0,r0) if f.rfind('<w:r ',0,r0)>f.rfind('<w:r>',0,r0) else f.rfind('<w:r>',0,r0)
    endm='<w:fldChar w:fldCharType="end"/>'; e1=f.index(endm,k); r1=f.index('</w:r>',e1)+6
    mt=re.search(r'<w:r[^>]*>(<w:rPr>(?:(?!</w:rPr>).)*</w:rPr>)?<w:t[^>]*>Corp-M2-QM',f[r0:r1],re.S)   # keep the character format of the field result (caps, grey)
    rpr=mt.group(1) if mt and mt.group(1) else ''
    f=f[:r0]+'<w:r>'+rpr+'<w:t>'+esc(props['footer_name'])+'</w:t></w:r>'+f[r1:]
    open(fp,'w',encoding='utf8').write(f)
    # numbering: bullets 90 + numbered lists
    npth=pkg+'/word/numbering.xml'; n=open(npth,encoding='utf8').read()
    absn='<w:abstractNum w:abstractNumId="90"><w:multiLevelType w:val="hybridMultilevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="-37" w:hanging="360"/></w:pPr><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial" w:hint="default"/></w:rPr></w:lvl></w:abstractNum><w:abstractNum w:abstractNumId="91"><w:multiLevelType w:val="hybridMultilevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="-37" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>'
    i=n.index('<w:num '); n=n[:i]+absn+n[i:]
    nums='<w:num w:numId="90"><w:abstractNumId w:val="90"/></w:num>'+''.join('<w:num w:numId="%d"><w:abstractNumId w:val="91"/><w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>'%k for k in doc.nums)
    n=n.replace('</w:numbering>',nums+'</w:numbering>'); open(npth,'w',encoding='utf8').write(n)
    # rels
    rp=pkg+'/word/_rels/document.xml.rels'; r=open(rp,encoding='utf8').read()
    r=r.replace('</Relationships>',''.join('<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/%s"/>'%(a,b) for a,b in doc.imgs)+'</Relationships>')
    open(rp,'w',encoding='utf8').write(r)
    ct=pkg+'/[Content_Types].xml'; c=open(ct,encoding='utf8').read()
    if 'Extension="png"' not in c: c=c.replace('<Override','<Default Extension="png" ContentType="image/png"/><Override',1)
    open(ct,'w',encoding='utf8').write(c)
    # core title
    cp=pkg+'/docProps/core.xml'; cc=open(cp,encoding='utf8').read()
    cc=re.sub(r'<dc:title>.*?</dc:title>','<dc:title>'+esc(doc.title)+'</dc:title>',cc)
    cc=re.sub(r'<dc:creator>.*?</dc:creator>','<dc:creator>'+esc(props['author'])+'</dc:creator>',cc)
    cc=re.sub(r'<cp:lastModifiedBy>.*?</cp:lastModifiedBy>','<cp:lastModifiedBy>'+esc(props['author'])+'</cp:lastModifiedBy>',cc)
    import datetime; now=datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    cc=re.sub(r'(<dcterms:created[^>]*>).*?(</dcterms:created>)',r'\g<1>'+now+r'\g<2>',cc); cc=re.sub(r'(<dcterms:modified[^>]*>).*?(</dcterms:modified>)',r'\g<1>'+now+r'\g<2>',cc)
    open(cp,'w',encoding='utf8').write(cc)
    if os.path.exists(outpath): os.remove(outpath)
    with zipfile.ZipFile(outpath,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(pkg+'/[Content_Types].xml','[Content_Types].xml')
        for top in ('_rels','docProps','word','customXml'):
            for root,_,files in os.walk(os.path.join(pkg,top)):
                for fn in sorted(files):
                    full=os.path.join(root,fn); z.write(full,os.path.relpath(full,pkg).replace(os.sep,'/'))
    shutil.rmtree(work,ignore_errors=True)
