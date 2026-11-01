"""Public source text monitor. No legal interpretation, credentials or user URLs."""
import concurrent.futures
from collections import Counter
from datetime import datetime, timezone
import difflib
import hashlib
import logging
from email.utils import parsedate_to_datetime
import host_throttle
import bounded_ocr
import bounded_docx
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
SOURCE_SECONDS=90
RUN_SECONDS=720

NEXT_ACTIONS={
    'BLOCKED':'Review publisher access policy; do not bypass access controls.',
    'NOT_FOUND':'Manually verify the exact source URL with the publisher.',
    'PARSER_ERROR':'Review the source document; scanned PDFs require a verified text source or manual review.',
    'TIMEOUT':'Retry during a later scheduled run within the same time limits.',
    'DNS':'Verify publisher DNS; retry transient resolution failures later.',
    'TLS':'Ask the publisher to correct TLS; certificate verification remains required.',
    'NETWORK':'Retry transient network failures during a later run.',
    'REDIRECT':'Review the redirect destination before any allowlist change.',
    'LIMIT':'Review the source manually; automated size and resource limits remain enforced.',
    'HTTP_ERROR':'Review the publisher HTTP response; retry only transient server errors.',
    'SECURITY':'Review the exact URL and destination against the security policy.',
    'INTERNAL':'Inspect the monitor environment and dependency installation.',
    'UNKNOWN':'Inspect diagnostic evidence; no specific cause has been inferred.',
}
class MonitorError(ValueError):
    def __init__(self,category,code,detail,http_status=None,retryable=False,retry_after=None,attempts=0):
        super().__init__(code)
        self.category=category;self.code=code;self.detail=detail
        self.http_status=http_status;self.retryable=retryable;self.retry_after=retry_after;self.attempts=attempts
    def as_dict(self):
        return {'error':self.code,'errorCategory':self.category,'errorCode':self.code,
                'httpStatus':self.http_status,'attempts':self.attempts,'detail':self.detail,
                'nextAction':NEXT_ACTIONS[self.category]}

def error_info(exc,attempts=0):
    if isinstance(exc,MonitorError):
        if attempts:exc.attempts=attempts
        return exc
    if isinstance(exc,(TimeoutError,subprocess.TimeoutExpired)):
        error=MonitorError('TIMEOUT','SOURCE_TIMEOUT','The bounded source operation timed out.',retryable=True)
    elif isinstance(exc,socket.gaierror):
        error=MonitorError('DNS','DNS_RESOLUTION','Public hostname resolution failed.',retryable=exc.errno==socket.EAI_AGAIN)
    elif isinstance(exc,ssl.SSLError):
        error=MonitorError('TLS','TLS_VERIFICATION' if isinstance(exc,ssl.SSLCertVerificationError) else 'TLS_HANDSHAKE','TLS negotiation or certificate verification failed.')
    elif isinstance(exc,MemoryError):
        error=MonitorError('LIMIT','MEMORY_LIMIT','The parser exhausted its bounded memory budget.')
    elif isinstance(exc,(ConnectionError,http.client.HTTPException,OSError)):
        error=MonitorError('NETWORK','NETWORK_'+type(exc).__name__.upper(),'The network operation failed ('+type(exc).__name__+').',retryable=True)
    elif isinstance(exc,ModuleNotFoundError):
        error=MonitorError('INTERNAL','MISSING_DEPENDENCY','A required parser dependency is unavailable.')
    elif isinstance(exc,ValueError) and str(exc) in ('UNSAFE_URL','IP_LITERAL_DENIED','PRIVATE_DESTINATION','NOT_ALLOWLISTED'):
        error=MonitorError('SECURITY',str(exc),'The URL or resolved destination was rejected by the security policy.')
    else:
        error=MonitorError('UNKNOWN','UNEXPECTED_ERROR','Unexpected '+type(exc).__name__+'; response bodies and exception text are withheld.')
    error.attempts=attempts
    return error

def retry_after_seconds(value,now=None):
    if not value:return None
    if re.fullmatch(r'\d{1,10}',value.strip()):return float(value)
    try:
        when=parsedate_to_datetime(value)
        if when.tzinfo is None:when=when.replace(tzinfo=timezone.utc)
        return max(0.0,when.timestamp()-(time.time() if now is None else now))
    except (TypeError,ValueError,OverflowError):return None

def http_error(status,retry_after=None):
    category='BLOCKED' if status in (401,403,429) else 'NOT_FOUND' if status in (404,410) else 'HTTP_ERROR'
    return MonitorError(category,'HTTP_'+str(status),'Publisher returned HTTP '+str(status)+'.',status,status in (429,500,502,503,504),retry_after)

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


def extract(body,content_type,deadline=None,metadata=None):
    metadata={} if metadata is None else metadata
    deadline=deadline or time.monotonic()+SOURCE_SECONDS-2
    kind=content_type.lower()
    if body.startswith(b'%PDF-'):
        try:
            from pypdf import PdfReader
            # Keep strict parsing: no observed evidence justifies accepting malformed PDFs.
            reader=PdfReader(io.BytesIO(body),strict=True)
            if reader.is_encrypted:
                if not reader.decrypt(''):raise MonitorError('PARSER_ERROR','PDF_ENCRYPTED','PDF requires a nonempty password; manual review is required.')
                metadata.update(publicEmptyPassword=True,reviewRequired=True)
            if len(reader.pages)>500:raise MonitorError('LIMIT','PDF_PAGE_LIMIT','PDF exceeds the 500-page processing limit.')
            parts=[];size=0;needs_ocr=False;blank_pages=[]
            for number,page in enumerate(reader.pages,1):
                part=page.extract_text() or ''
                if not part.strip():
                    contents=page.get_contents()
                    if contents is None or not contents.get_data().strip():blank_pages.append(number)
                    else:needs_ocr=True
                size+=len(part.encode('utf-8'))
                if size>TEXT_LIMIT:raise MonitorError('LIMIT','TEXT_LIMIT','Extracted text exceeds the text size limit.')
                parts.append(part)
            text='\n'.join(parts)
        except (MonitorError,MemoryError,ModuleNotFoundError):raise
        except Exception as exc:
            if type(exc).__name__=='DependencyError':raise MonitorError('INTERNAL','MISSING_PDF_CRYPTO','The PDF requires the optional cryptography parser dependency.') from exc
            raise MonitorError('PARSER_ERROR','PDF_PARSE_ERROR','PDF parsing failed ('+type(exc).__name__+').') from exc
        if needs_ocr or not text.strip():
            if len(blank_pages)==len(reader.pages):raise MonitorError('PARSER_ERROR','PDF_EMPTY_TEXT','PDF contains only blank pages.')
            try:text,ocr_metadata=bounded_ocr.extract_pdf(body,len(reader.pages),deadline,TEXT_LIMIT,blank_pages)
            except bounded_ocr.OCRFailure as exc:raise MonitorError(exc.category,exc.code,exc.detail) from exc
            metadata.update(ocr_metadata)
        else:metadata['extractionMethod']='PDF_TEXT'
    elif body.startswith(b'PK\x03\x04') or 'wordprocessingml.document' in kind:
        try:text=bounded_docx.extract_docx(body,TEXT_LIMIT)
        except bounded_docx.DOCXFailure as exc:raise MonitorError(exc.category,exc.code,exc.detail) from exc
        metadata.update(extractionMethod='DOCX_TEXT',reviewRequired=True)
    elif 'html' in kind:
        metadata['extractionMethod']='HTML_TEXT'
        charset=re.search(r'charset\s*=\s*["\']?([a-zA-Z0-9._-]+)',kind)
        encoding=charset.group(1) if charset else 'utf-8'
        try:raw=body.decode(encoding,errors='replace')
        except LookupError:raise MonitorError('PARSER_ERROR','TEXT_ENCODING','Publisher declared an unsupported character encoding.')
        parser=VisibleText()
        try:parser.feed(raw);text=''.join(parser.parts)
        except Exception as exc:raise MonitorError('PARSER_ERROR','HTML_PARSE_ERROR','HTML parsing failed ('+type(exc).__name__+').') from exc
        visible=normalize(text)
        prefix=visible[:2000]
        challenge=r'access denied|verify (?:that )?you are human|just a moment|checking your browser|request blocked|security verification'
        if re.search(challenge,prefix,re.I) or re.search(r'/cdn-cgi/challenge-platform/|_cf_chl_opt|g-recaptcha|hcaptcha',raw,re.I) and len(visible)<2000:
            raise MonitorError('BLOCKED','CHALLENGE_PAGE','Publisher returned an access-control or human-verification page.',200)
        if re.search(r'page (?:not found|does not exist)|404\s*(?:error|not found)|the requested (?:url|page) (?:was not found|could not be found)',prefix,re.I):
            raise MonitorError('NOT_FOUND','SOFT_404','Publisher returned a missing-page message with HTTP 200.',200)
        if len(visible)<500 and re.search(r'enable javascript|javascript (?:is required|must be enabled)|<div[^>]+id=["\'](?:root|app)["\']',raw,re.I):
            raise MonitorError('PARSER_ERROR','JS_SHELL','Page requires JavaScript and contains insufficient source text.',200)
    elif kind.startswith('text/plain'):
        metadata['extractionMethod']='PLAIN_TEXT'
        try:text=body.decode('utf-8',errors='strict')
        except UnicodeError:raise MonitorError('PARSER_ERROR','TEXT_ENCODING','Plain text is not valid UTF-8.')
    else:raise MonitorError('PARSER_ERROR','UNSUPPORTED_CONTENT','Response format is not supported by the bounded text parser.')
    text=normalize(text)
    if not text:raise MonitorError('PARSER_ERROR','EMPTY_TEXT','Response contains no extractable source text.')
    if len(text.encode('utf-8'))>TEXT_LIMIT:raise MonitorError('LIMIT','TEXT_LIMIT','Extracted text exceeds the text size limit.')
    return text

def fetch_once(url,config,deadline):
    hosts=set(config['hosts']);current=url
    for hop in range(4):
        p=validate_url(current,hosts)
        host_throttle.wait(p.hostname,deadline)
        address=resolve_public(p.hostname)
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError()
        conn=PinnedHTTPS(p.hostname,address,min(10,remaining))
        try:
            path=p.path or '/'
            if p.query:path+='?'+p.query
            conn.request('GET',path,headers={
                'User-Agent':'Mozilla/5.0 (compatible; CourtScanSourceMonitor/1.1; public legal-source monitoring)',
                'Accept':'text/html,application/xhtml+xml,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain;q=0.9',
                'Accept-Language':'en-US,en;q=0.9','Accept-Encoding':'identity','Connection':'close'})
            response=conn.getresponse()
            if response.status in (301,302,303,307,308):
                if hop==3:raise MonitorError('REDIRECT','REDIRECT_LIMIT','Redirect chain exceeds the four-hop request limit.')
                location=response.getheader('Location')
                if not location:raise MonitorError('REDIRECT','MISSING_REDIRECT','Redirect response has no Location header.')
                try:current=redirect_url(current,location,hosts)
                except ValueError as exc:raise MonitorError('REDIRECT','REDIRECT_DENIED','Redirect destination violates the HTTPS host allowlist.') from exc
                continue
            if response.status!=200:
                delay=retry_after_seconds(response.getheader('Retry-After'))
                if delay is not None and response.status in (429,503):
                    host_throttle.defer(p.hostname,delay,deadline)
                raise http_error(response.status,delay)
            if response.getheader('Content-Encoding','identity').lower()!='identity':
                raise MonitorError('PARSER_ERROR','ENCODING_UNSUPPORTED','Publisher ignored the identity content-encoding requirement.',200)
            try:length=int(response.getheader('Content-Length','0'))
            except ValueError:raise MonitorError('NETWORK','INVALID_CONTENT_LENGTH','Publisher returned an invalid Content-Length header.',200)
            if length<0:raise MonitorError('NETWORK','INVALID_CONTENT_LENGTH','Publisher returned a negative Content-Length header.',200)
            if length>BODY_LIMIT:raise MonitorError('LIMIT','BODY_LIMIT','Response exceeds the 8 MiB body limit.',200)
            body=bytearray()
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError()
                if conn.sock is not None:conn.sock.settimeout(min(10,remaining))
                chunk=response.read(65536)
                if not chunk:break
                body.extend(chunk)
                if len(body)>BODY_LIMIT:raise MonitorError('LIMIT','BODY_LIMIT','Response exceeds the 8 MiB body limit.',200)
            metadata={}
            try:text=extract(bytes(body),response.getheader('Content-Type',''),deadline,metadata)
            except Exception as exc:
                error=error_info(exc);error.http_status=200
                raise error from exc
            return {'text':text,'resolvedUrl':current,'httpStatus':200,**metadata}
        finally:conn.close()
    raise MonitorError('REDIRECT','REDIRECT_LIMIT','Redirect chain exceeds the four-hop request limit.')

def fetch_text(url,config):
    if url not in config['urls']:raise error_info(ValueError('NOT_ALLOWLISTED'))
    replacement=config.get('sourceReplacements',{}).get(url)
    target=url
    if replacement:
        if not isinstance(replacement,dict) or not all(isinstance(replacement.get(k),str) and replacement[k] for k in ('url','verifiedAt','evidenceUrl')):
            raise MonitorError('SECURITY','SOURCE_REPLACEMENT_INVALID','A replacement requires an exact reviewed URL and provenance.')
        target=replacement['url']
        validate_url(target,set(config['hosts']))
    # Outer worker enforces 90s even for DNS or parser calls that cannot be interrupted here.
    deadline=time.monotonic()+SOURCE_SECONDS-2
    history=[]
    for attempt in range(1,4):
        try:
            result=fetch_once(target,config,deadline)
            result['attempts']=attempt
            if replacement:result.update(reviewRequired=True,observedSourceChange=True,sourceReplacement={k:replacement[k] for k in ('url','verifiedAt','evidenceUrl','note') if k in replacement})
            if history:result['attemptErrors']=history
            return result
        except Exception as exc:
            error=error_info(exc,attempt)
            history.append(error.as_dict())
            delay=max(2**(attempt-1),error.retry_after or 0)
            if not error.retryable or attempt==3 or delay+1>=deadline-time.monotonic():raise error from exc
            time.sleep(delay)
    raise error
def digest(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()

def observe(url,text,previous,root,at,events,resolved_url=None,publish_text=True):
    text=normalize(text);new=digest(text);old=previous.get('hash')
    status='BASELINED' if not old else 'UNCHANGED' if old==new else 'CHANGED'
    if not publish_text:
        # Retain only hashes for third-party/uncleared content. Never persist or publish the text.
        if status!='UNCHANGED':
            events.append({'id':digest(url+'\n'+at+'\n'+new),'sourceUrl':url,'resolvedUrl':resolved_url or url,'time':at,'status':status,'previousHash':old,'newHash':new,'diff':None,'snapshot':None,'diffPolicy':'HASH_ONLY_RIGHTS_UNCLEARED'})
        return {**({'errorHistory':previous['errorHistory']} if previous.get('errorHistory') else {}),'sourceUrl':url,'resolvedUrl':resolved_url or url,'status':status,'checkedAt':at,'lastSuccessAt':at,'hash':new,'snapshot':None,'textPublication':'HASH_ONLY','reviewRequired':previous.get('reviewRequired',False) or status=='CHANGED'}
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
    return {**({'errorHistory':previous['errorHistory']} if previous.get('errorHistory') else {}),'sourceUrl':url,'resolvedUrl':resolved_url or url,'status':status,'checkedAt':at,'lastSuccessAt':at,'hash':new,'snapshot':relative,'reviewRequired':previous.get('reviewRequired',False) or status=='CHANGED'}


def failed(url,previous,at,error):
    if isinstance(error,MonitorError):error=error.as_dict()
    elif not isinstance(error,dict):
        error=MonitorError('UNKNOWN',str(error),'Legacy failure without more specific diagnostic evidence.').as_dict()
    fields={k:error.get(k) for k in ('error','errorCategory','errorCode','httpStatus','attempts','detail','nextAction')}
    history=list(previous.get('errorHistory',[]))
    history.append({'checkedAt':at,**fields})
    return {**previous,'sourceUrl':url,'status':'ERROR','checkedAt':at,**fields,'errorHistory':history[-12:]}
def update_record(record,urls,results,at):
    checks=[results[u] for u in urls]
    prior=record.get('sourceMonitoring') or {}
    review=prior.get('reviewRequired',False) or any(x.get('reviewRequired',False) or x['status']=='CHANGED' for x in checks)
    status='PENDING' if not checks else 'ERROR' if any(x['status']=='ERROR' for x in checks) else 'CHANGED' if any(x['status']=='CHANGED' for x in checks) else 'BASELINED' if any(x['status']=='BASELINED' for x in checks) else 'UNCHANGED'
    record['sourceMonitoring']={'status':status,'checkedAt':min(x['checkedAt'] for x in checks) if checks else None,'sourceUrls':urls,'reviewRequired':review,'textHashes':{u:results[u].get('hash') for u in urls}}
    if review:
        record['actionProfile']={**(record.get('actionProfile') or {}),'generationEligible':False}
        record['verificationLabel']='REVIEW_REQUIRED'


def worker(url,deadline,throttle_dir=None):
    remaining=deadline-time.monotonic()
    if remaining<=0:return MonitorError('LIMIT','RUN_TIME_BUDGET','The monitor run time budget was exhausted.').as_dict()
    try:
        env=os.environ.copy()
        if throttle_dir:env['COURTSCAN_THROTTLE_DIR']=str(throttle_dir)
        process=subprocess.run([sys.executable,str(ROOT/'monitor.py'),'--fetch',url],capture_output=True,text=True,encoding='utf-8',timeout=min(SOURCE_SECONDS,remaining),cwd=ROOT,env=env)
        try:result=json.loads(process.stdout)
        except (ValueError,TypeError):
            return MonitorError('INTERNAL','CHILD_PROCESS_ERROR','Fetch child ended without a valid structured result.').as_dict()
        if not isinstance(result,dict) or ('error' not in result and ('text' not in result or 'resolvedUrl' not in result)):
            return MonitorError('INTERNAL','CHILD_RESULT_INVALID','Fetch child returned an invalid result shape.').as_dict()
        if process.returncode and 'error' not in result:
            return MonitorError('INTERNAL','CHILD_PROCESS_ERROR','Fetch child ended unsuccessfully.').as_dict()
        return result
    except subprocess.TimeoutExpired:
        return MonitorError('TIMEOUT','SOURCE_TIMEOUT','The isolated fetch/parser exceeded its source time budget.',attempts=0).as_dict()
    except Exception as exc:return error_info(exc).as_dict()
def sync(root=ROOT):
    config=json.loads((root/'allowlist.json').read_text(encoding='utf-8'))
    dataset=json.loads((root/'data/court-rules.min.json').read_text(encoding='utf-8'))
    status=json.loads((root/'data/source-status.json').read_text(encoding='utf-8'))
    changelog=json.loads((root/'data/changelog.json').read_text(encoding='utf-8'))
    previous={x['sourceUrl']:x for x in status['sources']};events=changelog['events']
    # Prioritize sources deferred by the previous run, then least recent success.
    # This avoids starving later URLs when some hosts repeatedly time out.
    urls=sorted(config['urls'],key=lambda u:(previous.get(u,{}).get('error')!='RUN_TIME_BUDGET',previous.get(u,{}).get('lastSuccessAt',''),u));deadline=time.monotonic()+RUN_SECONDS
    with tempfile.TemporaryDirectory(prefix='courtscan-throttle-') as throttle_dir:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            fetched=dict(zip(urls,pool.map(lambda u:worker(u,deadline,throttle_dir),urls)))
    at=datetime.now(timezone.utc).isoformat();results={}
    for url in urls:
        result=fetched[url];old=previous.get(url,{})
        if 'error' in result:results[url]=failed(url,old,at,result)
        else:
            try:
                final_host=urlsplit(result['resolvedUrl']).hostname or ''
                publish_text=url in config.get('publicTextUrls',[]) and (final_host=='uscourts.gov' or final_host.endswith('.uscourts.gov') or final_host in ('www.govinfo.gov','www.federalregister.gov'))
                results[url]=observe(url,result['text'],old,root,result['observedAt'],events,result['resolvedUrl'],publish_text=publish_text)
                results[url].update(attempts=result.get('attempts',1),httpStatus=result.get('httpStatus',200))
                for field in ('extractionMethod','ocrPages','ocrMeanConfidence','ocrEmptyPages','publicEmptyPassword','observedSourceChange','sourceReplacement'):
                    if field in result:results[url][field]=result[field]
                results[url]['reviewRequired']=results[url]['reviewRequired'] or result.get('reviewRequired',False)
                if result.get('attemptErrors'):results[url]['attemptErrors']=result['attemptErrors']
            except Exception as exc:results[url]=failed(url,old,at,MonitorError('INTERNAL','SNAPSHOT_ERROR','Snapshot integrity or persistence failed ('+type(exc).__name__+').'))
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
    diagnostics={'time':at,'counts':status['counts'],'errorCategories':dict(Counter(x.get('errorCategory','UNKNOWN') for x in results.values() if x['status']=='ERROR')),'errors':[{'sourceUrl':u,'category':x.get('errorCategory','UNKNOWN'),**{k:x.get(k) for k in ('errorCategory','errorCode','httpStatus','attempts','detail','nextAction','lastSuccessAt')}} for u,x in results.items() if x['status']=='ERROR'],'recovered':[{'sourceUrl':u,'status':x['status'],'previousError':previous[u].get('errorCode',previous[u].get('error'))} for u,x in results.items() if x['status']!='ERROR' and previous.get(u,{}).get('status')=='ERROR']}
    atomic_json(root/'diagnostics.json',diagnostics)
    return 1 if errors else 0


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--fetch':
        logging.getLogger('pypdf').setLevel(logging.CRITICAL)
        try:
            if sys.platform!='win32':
                import resource
                resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
            result=fetch_text(sys.argv[2],json.loads((ROOT/'allowlist.json').read_text(encoding='utf-8')))
            result['observedAt']=datetime.now(timezone.utc).isoformat()
            print(json.dumps(result,ensure_ascii=True))
        except Exception as exc:
            print(json.dumps(error_info(exc).as_dict(),ensure_ascii=True))
            sys.exit(1)
    elif len(sys.argv)==1:sys.exit(sync())
    else:sys.exit('No user-supplied URL mode. Use the reviewed allowlist.')
