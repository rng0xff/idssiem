#!/usr/bin/env python3
"""Builds the Tool Management Record (docx + pdf) from the facts collected by tools/release-report.js.
usage: generate.py <facts.json> <config.json> <outdir>
The page numbers of the table of contents are filled in with a LibreOffice run (two passes); without LibreOffice / poppler the docx is
written without page numbers and without PDF (Word fills them in with 'Update field')."""
import sys, os, re, json, shutil, subprocess, tempfile
HERE=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,HERE)
import doclib, content

def find_soffice():
    for n in (os.environ.get('SOFFICE'),'soffice','libreoffice','soffice.exe'):
        if n and shutil.which(n): return shutil.which(n)
    for p in (r'C:\Program Files\LibreOffice\program\soffice.exe',r'C:\Program Files (x86)\LibreOffice\program\soffice.exe','/Applications/LibreOffice.app/Contents/MacOS/soffice'):
        if os.path.exists(p): return p
    return None
def to_pdf(soffice,docx,outdir):
    import pathlib
    prof=tempfile.mkdtemp(prefix='lo-profile-')   # own profile: works while another LibreOffice instance is open
    subprocess.run([soffice,'-env:UserInstallation='+pathlib.Path(prof).as_uri(),'--headless','--convert-to','pdf','--outdir',outdir,docx],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    shutil.rmtree(prof,ignore_errors=True)
    return os.path.join(outdir,os.path.splitext(os.path.basename(docx))[0]+'.pdf')
def pdf_pages(pdf):
    if not shutil.which('pdftotext') or not shutil.which('pdfinfo'): return None
    n=int(re.search(r'Pages:\s+(\d+)',subprocess.check_output(['pdfinfo',pdf]).decode()).group(1))
    return [subprocess.check_output(['pdftotext','-f',str(i),'-l',str(i),'-layout',pdf,'-']).decode('utf8','replace') for i in range(1,n+1)]
norm=lambda t: re.sub(r'\s+',' ',t).strip().lower()
def heading_pages(doc,pages):
    start=0
    for i,p in enumerate(pages):
        if 'CONTENT' in p and ('___' in p or '....' in p): start=i+1
    while start<len(pages) and '___' in pages[start] and 'CONTENT' not in pages[start]: start+=1
    cur=start; res={}
    for lv,text,name in doc.heads:
        t=norm(text); found=None
        for i in range(cur,len(pages)):
            for ln in pages[i].split('\n'):
                if '___' in ln: continue
                l=norm(ln)
                if l.endswith(t) and len(l)-len(t)<=8: found=i; break
            if found is not None: break
        if found is None: found=cur
        cur=found; res[name]=str(found+1)
    return res

def main(facts_path,cfg_path,outdir):
    F=json.load(open(facts_path,encoding='utf8')); cfg=json.load(open(cfg_path,encoding='utf8'))
    os.makedirs(outdir,exist_ok=True)
    base=(cfg['docNumber']+'-' if cfg['docNumber'] else '')+cfg['fileTitle']   # empty docNumber: no number in the file name and the header
    docx=os.path.join(outdir,base+'.docx'); props={'author':cfg['owner'],'footer_name':base+'.docx'}
    soffice=find_soffice(); pages={}; pdf=None
    for it in range(2 if soffice else 1):
        doc=content.make(F,cfg)
        doclib.make_pkg(doc,pages,docx,props)
        if soffice:
            work=tempfile.mkdtemp(prefix='tm-pdf-'); pdf_tmp=to_pdf(soffice,docx,work)
            pg=pdf_pages(pdf_tmp)
            if pg is None: print('note: pdftotext/pdfinfo (poppler) not found – table of contents without page numbers'); 
            else: pages=heading_pages(doc,pg)
            if it==1 or pg is None:
                pdf=os.path.join(outdir,base+'.pdf'); shutil.copy(pdf_tmp,pdf)
            shutil.rmtree(work,ignore_errors=True)
            if pg is None: break
    if not soffice: print('note: LibreOffice not found – only the docx was written (set SOFFICE or install LibreOffice for the PDF and the page numbers)')
    print('written:',docx); 
    if pdf: print('written:',pdf)
    if getattr(doc,'unassessed',None): print('WARNING: informational test lines not assessed:',', '.join(doc.unassessed))
if __name__=='__main__': main(*sys.argv[1:4])
