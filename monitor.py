"""Public source text monitor. No legal interpretation, credentials or user URLs."""
import concurrent.futures
from collections import Counter
from datetime import datetime, timezone
import difflib
import hashlib
from html.parser import HTMLParser
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unicodedata
from urllib.parse import urlsplit, urljoin, urldefrag

ROOT=Path(__file__).resolve().parent
BODY_LIMIT=8*1024*1024
TEXT_LIMIT=2*1024*1024
SOURCE_SECONDS=40
RUN_SECONDS=600

def atomic_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    data=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n'
    fd,name=tempfile.mkstemp(prefix='.pending-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def atomic_snapshot(path,text):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.pending-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            f.write(text);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def record_urls(record):
    values=[record.get('sourceUrl')]
    values += [x if isinstance(x,str) else x.get('url') or x.get('href') or x.get('sourceUrl') for x in record.get('sourceLinks',[]) if x]
    return sorted({x for x in values if isinstance(x,str) and x})

def validate_url(url,hosts):
    if not isinstance(url,str) or len(url)>4096 or re.search(r'[\x00-\x20\x7f\\]',url):raise ValueError('UNSAFE_URL')
    p=urlsplit(url)
    if p.scheme!='https' or p.username or p.password or p.port not in (None,443) or not p.hostname or p.hostname not in hosts:raise ValueError('UNSAFE_URL')
    try:ipaddress.ip_address(p.hostname)
    except ValueError:pass
    else:raise ValueError('IP_LITERAL_DENIED')
    return p

def resolve_public(host):
    addresses=sorted({a[4][0] for a in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):raise ValueError('PRIVATE_DESTINATION')
    return addresses[0]

def redirect_url(current,location,hosts):
    target=urldefrag(urljoin(current,location))[0]
    validate_url(target,hosts)
    return target

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,address,timeout):
        super().__init__(host,timeout=timeout,context=ssl.create_default_context());self.address=address
    def connect(self):
        # Connect to the validated address, preserving TLS SNI/hostname verification.
        # No proxy environment and no second DNS lookup (rebinding protection).
        sock=socket.create_connection((self.address,443),self.timeout)
        self.sock=self._context.wrap_socket(sock,server_hostname=self.host)

class VisibleText(HTMLParser):
    def __init__(self):super().__init__(convert_charrefs=True);self.parts=[];self.skip=0
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style','noscript','template'):self.skip+=1
        if not self.skip and tag in ('p','div','br','li','h1','h2','h3','tr','section'):self.parts.append('\n')
    def handle_endtag(self,tag):
        if tag in ('script','style','noscript','template') and self.skip:self.skip-=1
        if not self.skip and tag in ('p','div','li','section'):self.parts.append('\n')
    def handle_data(self,data):
        if not self.skip:self.parts.append(data)

def normalize(text):
    return '\n'.join(' '.join(line.split()) for line in unicodedata.normalize('NFKC',text).replace('\r','\n').splitlines() if line.strip())

def extract(body,content_type):
    if body.startswith(b'%PDF-'):
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(body),strict=True)
        if reader.is_encrypted or len(reader.pages)>500:raise ValueError('PDF_UNSUPPORTED')
        text='\n'.join(page.extract_text() or '' for page in reader.pages)
    elif 'html' in content_type:
        parser=VisibleText();parser.feed(body.decode('utf-8',errors='replace'));text=''.join(parser.parts)
    elif content_type.startswith('text/plain'):text=body.decode('utf-8',errors='strict')
    else:raise ValueError('UNSUPPORTED_CONTENT')
    text=normalize(text)
    if not text or len(text.encode('utf-8'))>TEXT_LIMIT:raise ValueError('EMPTY_OR_OVERSIZE_TEXT')
    if re.search(r'access denied|verify you are human|just a moment|captcha|request blocked|page not found',text[:2000],re.I):raise ValueError('CHALLENGE_OR_ERROR_PAGE')
    return text

def fetch_text(url,config):
    if url not in config['urls']:raise ValueError('NOT_ALLOWLISTED')
    hosts=set(config['hosts']);current=url;deadline=time.monotonic()+SOURCE_SECONDS-2
    for hop in range(4):
        p=validate_url(current,hosts);address=resolve_public(p.hostname)
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError()
        conn=PinnedHTTPS(p.hostname,address,min(10,remaining))
        try:
            path=p.path or '/'
            if p.query:path+='?'+p.query
            conn.request('GET',path,headers={'User-Agent':'CourtScanSourceMonitor/1.0 (public source text checks)','Accept':'application/pdf,text/html,text/plain','Accept-Encoding':'identity'})
            response=conn.getresponse()
            if response.status in (301,302,303,307,308):
                if hop==3:raise ValueError('REDIRECT_LIMIT')
                location=response.getheader('Location')
                if not location:raise ValueError('MISSING_REDIRECT')
                current=redirect_url(current,location,hosts);continue
            if response.status!=200:raise ValueError('HTTP_'+str(response.status))
            if response.getheader('Content-Encoding','identity')!='identity':raise ValueError('ENCODING_UNSUPPORTED')
            if int(response.getheader('Content-Length','0'))>BODY_LIMIT:raise ValueError('BODY_LIMIT')
            body=bytearray()
            while True:
                if time.monotonic()>deadline:raise TimeoutError()
                chunk=response.read(65536)
                if not chunk:break
                body.extend(chunk)
                if len(body)>BODY_LIMIT:raise ValueError('BODY_LIMIT')
            return {'text':extract(bytes(body),response.getheader('Content-Type','')),'resolvedUrl':current}
        finally:conn.close()
    raise ValueError('REDIRECT_LIMIT')

def digest(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()

def observe(url,text,previous,root,at,events,resolved_url=None,publish_text=True):
    text=normalize(text);new=digest(text);old=previous.get('hash')
    status='BASELINED' if not old else 'UNCHANGED' if old==new else 'CHANGED'
    if not publish_text:
        # Retain only hashes for third-party/uncleared content. Never persist or publish the text.
        if status!='UNCHANGED':
            events.append({'id':digest(url+'\n'+at+'\n'+new),'sourceUrl':url,'resolvedUrl':resolved_url or url,'time':at,'status':status,'previousHash':old,'newHash':new,'diff':None,'snapshot':None,'diffPolicy':'HASH_ONLY_RIGHTS_UNCLEARED'})
        return {'sourceUrl':url,'resolvedUrl':resolved_url or url,'status':status,'checkedAt':at,'lastSuccessAt':at,'hash':new,'snapshot':None,'textPublication':'HASH_ONLY','reviewRequired':previous.get('reviewRequired',False) or status=='CHANGED'}
    relative='snapshots/'+new+'.txt';target=root/relative
    if target.exists():
        if digest(target.read_text(encoding='utf-8'))!=new:raise ValueError('SNAPSHOT_CORRUPTION')
    else:
        target.parent.mkdir(parents=True,exist_ok=True)
        # Immutable content-addressed files; the data manifest is written last.
        atomic_snapshot(target,text)
    if status!='UNCHANGED':
        before=''
        if old:
            before=(root/('snapshots/'+old+'.txt')).read_text(encoding='utf-8')
            if digest(before)!=old:raise ValueError('SNAPSHOT_CORRUPTION')
        diff='\n'.join(difflib.unified_diff(before.splitlines(),text.splitlines(),fromfile='previous',tofile='current',lineterm=''))
        events.append({'id':digest(url+'\n'+at+'\n'+new),'sourceUrl':url,'resolvedUrl':resolved_url or url,'time':at,'status':status,'previousHash':old,'newHash':new,'diff':diff,'snapshot':relative})
    return {'sourceUrl':url,'resolvedUrl':resolved_url or url,'status':status,'checkedAt':at,'lastSuccessAt':at,'hash':new,'snapshot':relative,'reviewRequired':previous.get('reviewRequired',False) or status=='CHANGED'}

def failed(url,previous,at,category):
    return {**previous,'sourceUrl':url,'status':'ERROR','checkedAt':at,'error':category}

def update_record(record,urls,results,at):
    checks=[results[u] for u in urls]
    prior=record.get('sourceMonitoring') or {}
    review=prior.get('reviewRequired',False) or any(x.get('reviewRequired',False) or x['status']=='CHANGED' for x in checks)
    status='PENDING' if not checks else 'ERROR' if any(x['status']=='ERROR' for x in checks) else 'CHANGED' if any(x['status']=='CHANGED' for x in checks) else 'BASELINED' if any(x['status']=='BASELINED' for x in checks) else 'UNCHANGED'
    record['sourceMonitoring']={'status':status,'checkedAt':min(x['checkedAt'] for x in checks) if checks else None,'sourceUrls':urls,'reviewRequired':review,'textHashes':{u:results[u].get('hash') for u in urls}}
    if review:
        record['actionProfile']={**(record.get('actionProfile') or {}),'generationEligible':False}
        record['verificationLabel']='REVIEW_REQUIRED'

def worker(url,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:return {'error':'RUN_TIME_BUDGET'}
    try:
        process=subprocess.run([sys.executable,str(ROOT/'monitor.py'),'--fetch',url],capture_output=True,text=True,encoding='utf-8',timeout=min(SOURCE_SECONDS,remaining),cwd=ROOT)
        if process.returncode:return {'error':'FETCH_OR_EXTRACTION_ERROR'}
        return json.loads(process.stdout)
    except subprocess.TimeoutExpired:return {'error':'TIMEOUT'}
    except Exception:return {'error':'WORKER_ERROR'}

def sync(root=ROOT):
    config=json.loads((root/'allowlist.json').read_text(encoding='utf-8'))
    dataset=json.loads((root/'data/court-rules.min.json').read_text(encoding='utf-8'))
    status=json.loads((root/'data/source-status.json').read_text(encoding='utf-8'))
    changelog=json.loads((root/'data/changelog.json').read_text(encoding='utf-8'))
    previous={x['sourceUrl']:x for x in status['sources']};events=changelog['events']
    # Prioritize sources deferred by the previous run, then least recent success.
    # This avoids starving later URLs when some hosts repeatedly time out.
    urls=sorted(config['urls'],key=lambda u:(previous.get(u,{}).get('error')!='RUN_TIME_BUDGET',previous.get(u,{}).get('lastSuccessAt',''),u));deadline=time.monotonic()+RUN_SECONDS
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        fetched=dict(zip(urls,pool.map(lambda u:worker(u,deadline),urls)))
    at=datetime.now(timezone.utc).isoformat();results={}
    for url in urls:
        result=fetched[url];old=previous.get(url,{})
        if 'error' in result:results[url]=failed(url,old,at,result['error'])
        else:
            try:
                final_host=urlsplit(result['resolvedUrl']).hostname or ''
                publish_text=url in config.get('publicTextUrls',[]) and (final_host=='uscourts.gov' or final_host.endswith('.uscourts.gov') or final_host in ('www.govinfo.gov','www.federalregister.gov'))
                results[url]=observe(url,result['text'],old,root,result['observedAt'],events,result['resolvedUrl'],publish_text=publish_text)
            except Exception:results[url]=failed(url,old,at,'SNAPSHOT_ERROR')
    for record in dataset['records']:update_record(record,[u for u in record_urls(record) if u in results],results,at)
    labels=Counter(r.get('verificationLabel','UNKNOWN') for r in dataset['records'])
    dataset.update(generatedAt=at,datasetDate=at[:10],date=at[:10],monitorRunId=at)
    dataset['counts'].update(records=len(dataset['records']),primaryReviewed=labels['PRIMARY_SOURCE_REVIEWED'],publisherReported=labels['PUBLISHER_REPORTED'],reviewRequired=labels['REVIEW_REQUIRED'],verificationLabels=dict(labels))
    counts=Counter(x['status'] for x in results.values());errors=counts['ERROR']
    status.update(generatedAt=at,runId=at,status='PARTIAL_ERROR' if errors else 'OK',sources=list(results.values()),counts={'allowlisted':len(urls),'monitored':len(urls)-errors,'errors':errors,'pending':0,'skipped':len(config['skipped']),'states':dict(counts)})
    changelog.update(generatedAt=at,runId=at)
    # Individual atomic writes. runId detects interrupted/mixed publication in consumers.
    atomic_json(root/'data/changelog.json',changelog)
    atomic_json(root/'data/court-rules.min.json',dataset)
    atomic_json(root/'data/source-status.json',status)
    atomic_json(root/'diagnostics.json',{'time':at,'counts':status['counts'],'errors':[{'sourceUrl':u,'category':x.get('error')} for u,x in results.items() if x['status']=='ERROR']})
    return 1 if errors else 0

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--fetch':
        try:
            if sys.platform!='win32':
                import resource
                resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
            result=fetch_text(sys.argv[2],json.loads((ROOT/'allowlist.json').read_text(encoding='utf-8')))
            result['observedAt']=datetime.now(timezone.utc).isoformat()
            print(json.dumps(result,ensure_ascii=True))
        except Exception:sys.exit(1)
    elif len(sys.argv)==1:sys.exit(sync())
    else:sys.exit('No user-supplied URL mode. Use the reviewed allowlist.')
