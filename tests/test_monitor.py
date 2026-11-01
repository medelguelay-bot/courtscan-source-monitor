import copy
import json
from pathlib import Path
import tempfile
import unittest
import sys
import uuid
import shutil
from contextlib import contextmanager
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from unittest.mock import patch
import monitor

URL='https://court.example/order'
@contextmanager
def workspace_temp():
    # Default-mode workspace directories avoid Windows TemporaryDirectory's
    # owner-only ACL, which excludes the managed runner's restricted token.
    parent=Path(__file__).resolve().parent
    folder=parent/('fixture-'+uuid.uuid4().hex)
    folder.mkdir()
    try:yield folder
    finally:
        if folder.resolve().parent!=parent or not folder.name.startswith('fixture-'):
            raise RuntimeError('Refusing cleanup outside test directory')
        shutil.rmtree(folder)
class MonitorTests(unittest.TestCase):
    def test_semantic_lifecycle_and_historical_review(self):
        record={'id':'judge','summary':'Do not rewrite me','status':'in-force','verificationLabel':'PRIMARY_SOURCE_REVIEWED','primaryReview':{'checkedAt':'2026-01-01'},'actionProfile':{'generationEligible':True}}
        with workspace_temp() as td:
            root=Path(td); previous={}; events=[]
            baseline=monitor.observe(URL,'First legal text',previous,root,'2026-11-01T06:17:00Z',events)
            self.assertEqual(baseline['status'],'BASELINED');self.assertEqual(events[0]['previousHash'],None)
            same=monitor.observe(URL,' First  legal text ',baseline,root,'2026-11-02T06:17:00Z',events)
            self.assertEqual(same['status'],'UNCHANGED');self.assertEqual(len(events),1)
            changed=monitor.observe(URL,'Revised legal text',same,root,'2026-11-03T06:17:00Z',events)
            self.assertEqual(changed['status'],'CHANGED');self.assertIn('-First legal text',events[-1]['diff']);self.assertIn('+Revised legal text',events[-1]['diff'])
            monitor.update_record(record,[URL],{URL:changed},'2026-11-03T06:17:00Z')
            self.assertTrue(record['sourceMonitoring']['reviewRequired']);self.assertFalse(record['actionProfile']['generationEligible']);self.assertEqual(record['verificationLabel'],'REVIEW_REQUIRED')
            self.assertEqual(record['primaryReview'],{'checkedAt':'2026-01-01'});self.assertEqual(record['summary'],'Do not rewrite me');self.assertEqual(record['status'],'in-force')
            again=monitor.observe(URL,'Revised legal text',changed,root,'2026-11-04T06:17:00Z',events)
            monitor.update_record(record,[URL],{URL:again},'2026-11-04T06:17:00Z')
            self.assertTrue(record['sourceMonitoring']['reviewRequired']);self.assertFalse(record['actionProfile']['generationEligible'])
            self.assertEqual(len(events),2)
            for event in events:self.assertTrue((root/event['snapshot']).exists())

    def test_error_never_unchanged_and_recovery_keeps_baseline(self):
        with workspace_temp() as td:
            root=Path(td);events=[]
            first=monitor.observe(URL,'Old text',{},root,'2026-11-01T00:00:00Z',events)
            failure=monitor.failed(URL,first,'2026-11-02T00:00:00Z','FETCH_ERROR')
            self.assertEqual(failure['status'],'ERROR');self.assertEqual(failure['hash'],first['hash'])
            r={'id':'x','actionProfile':{'generationEligible':True}}
            monitor.update_record(r,[URL],{URL:failure},'2026-11-02T00:00:00Z')
            self.assertEqual(r['sourceMonitoring']['status'],'ERROR')
            changed=monitor.observe(URL,'New text',failure,root,'2026-11-03T00:00:00Z',events)
            self.assertEqual(changed['status'],'CHANGED')

    def test_hostile_urls_dns_and_redirects(self):
        allowed={'court.example'}
        for url in ['http://court.example/a','https://user:pass@court.example/a','https://127.0.0.1/a','https://[::1]/a','https://court.example:444/a','https://court.example/a\r\nX:y','https://evil.example/a']:
            with self.assertRaises(ValueError):monitor.validate_url(url,allowed)
        for address in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','fc00::1']:
            with patch('monitor.socket.getaddrinfo',return_value=[(2,1,6,'',(address,443))]):
                with self.assertRaises(ValueError):monitor.resolve_public('court.example')
        with self.assertRaises(ValueError):monitor.redirect_url(URL,'https://evil.example/a',allowed)
        with self.assertRaises(ValueError):monitor.redirect_url(URL,'http://court.example/a',allowed)
        self.assertEqual(monitor.redirect_url(URL,'/new',allowed),'https://court.example/new')

    def test_html_text_and_empty_or_challenge_are_errors(self):
        self.assertEqual(monitor.extract(b'<html><script>secret()</script><p>Legal rule</p><style>x</style></html>','text/html'),'Legal rule')
        for body in [b'<html><script>x</script></html>',b'<html><title>Access denied</title></html>']:
            with self.assertRaises(ValueError):monitor.extract(body,'text/html')


    def test_uncleared_text_is_hash_only_and_still_detects_change(self):
        with workspace_temp() as td:
            root=Path(td);events=[]
            first=monitor.observe(URL,'Third party text never published',{},root,'2026-11-01T00:00:00Z',events,publish_text=False)
            self.assertEqual(first['status'],'BASELINED');self.assertIsNone(first['snapshot'])
            changed=monitor.observe(URL,'Different third party text',first,root,'2026-11-02T00:00:00Z',events,publish_text=False)
            self.assertEqual(changed['status'],'CHANGED');self.assertTrue(changed['reviewRequired'])
            self.assertNotEqual(first['hash'],changed['hash'])
            self.assertIsNone(events[-1]['diff']);self.assertEqual(events[-1]['diffPolicy'],'HASH_ONLY_RIGHTS_UNCLEARED')
            self.assertFalse(list(root.rglob('*.txt')))
            self.assertNotIn('Third party text',json.dumps(events))

    def test_atomic_publication_and_manifest_scope(self):
        with workspace_temp() as td:
            p=Path(td)/'state.json';monitor.atomic_json(p,{'status':'ERROR'});self.assertEqual(json.loads(p.read_text())['status'],'ERROR')
        base=Path(__file__).resolve().parents[1]
        config=json.loads((base/'allowlist.json').read_text(encoding='utf-8'))
        dataset=json.loads((base/'data/court-rules.min.json').read_text(encoding='utf-8'))
        actual={u for r in dataset['records'] for u in monitor.record_urls(r)}
        def assert_manifest_scope(candidate):
            original=set(candidate['urls']);skipped=set(candidate['skipped'])
            # Reviewed replacements supplement the 292 original monitored URLs.
            # They cannot remove history, expand arbitrary scope or become new sources.
            self.assertEqual(len(candidate['urls']),292)
            self.assertEqual(len(original),292)
            self.assertFalse(original & skipped)
            replacements=candidate.get('sourceReplacements',{})
            self.assertTrue(set(replacements).issubset(original))
            targets=set()
            for previous,replacement in replacements.items():
                self.assertIn(previous,original)
                self.assertIsInstance(replacement,dict)
                for field in ('url','verifiedAt','evidenceUrl','note'):
                    self.assertIsInstance(replacement.get(field),str)
                    self.assertTrue(replacement[field].strip())
                monitor.validate_url(replacement['url'],set(candidate['hosts']))
                if 'adapter' in replacement:monitor.cacd_adapter.validate(replacement['adapter'],replacement['url'],previous)
                self.assertIsNotNone(monitor.datetime.fromisoformat(replacement['verifiedAt']).tzinfo)
                targets.add(replacement['url'])
            self.assertEqual(original|skipped|targets,actual)

        assert_manifest_scope(config)
        # Even an HTTPS URL on an approved host must be the exact reviewed target.
        unapproved=copy.deepcopy(config)
        key=next(iter(unapproved['sourceReplacements']))
        unapproved['sourceReplacements'][key]['url']='https://apps.cacd.uscourts.gov/JpsApi/file/unapproved-review-fixture'
        with self.assertRaises(AssertionError):assert_manifest_scope(unapproved)



class ResilienceTests(unittest.TestCase):
    def setUp(self):
        self.config={'urls':[URL],'hosts':['court.example']}

    def test_http_classification_no_permanent_retries(self):
        for code,category in [(403,'BLOCKED'),(404,'NOT_FOUND'),(410,'NOT_FOUND'),(202,'HTTP_ERROR')]:
            with self.subTest(code=code),patch('monitor.fetch_once',side_effect=monitor.http_error(code)) as fetch,patch('monitor.time.sleep') as sleep:
                with self.assertRaises(monitor.MonitorError) as ctx:monitor.fetch_text(URL,self.config)
                evidence=ctx.exception.as_dict()
                self.assertEqual(evidence['errorCategory'],category)
                self.assertEqual(evidence['httpStatus'],code)
                self.assertEqual(evidence['attempts'],1)
                self.assertEqual(fetch.call_count,1);sleep.assert_not_called()

    def test_transient_retry_and_retry_after_respected(self):
        with patch('monitor.fetch_once',side_effect=[monitor.http_error(429,3),{'text':'Rule','resolvedUrl':URL}]) as fetch,patch('monitor.time.sleep') as sleep:
            result=monitor.fetch_text(URL,self.config)
            self.assertEqual(result['attempts'],2);sleep.assert_called_once_with(3)
            self.assertEqual(result['attemptErrors'][0]['httpStatus'],429)
        with patch('monitor.fetch_once',side_effect=monitor.http_error(503,3600)) as fetch,patch('monitor.time.sleep') as sleep:
            with self.assertRaises(monitor.MonitorError):monitor.fetch_text(URL,self.config)
            self.assertEqual(fetch.call_count,1);sleep.assert_not_called()
        with patch('monitor.fetch_once',side_effect=ConnectionResetError('secret body')) as fetch,patch('monitor.time.sleep'):
            with self.assertRaises(monitor.MonitorError) as ctx:monitor.fetch_text(URL,self.config)
            self.assertEqual(fetch.call_count,3);self.assertEqual(ctx.exception.attempts,3)
            self.assertNotIn('secret body',json.dumps(ctx.exception.as_dict()))

    def test_retry_after_dates_and_invalid_values(self):
        self.assertEqual(monitor.retry_after_seconds('Wed, 21 Oct 2015 07:28:00 GMT',1445412475),5)
        self.assertEqual(monitor.retry_after_seconds('15'),15)
        self.assertIsNone(monitor.retry_after_seconds('invalid'))
        self.assertIsNone(monitor.retry_after_seconds('-3'))

    def test_dns_tls_timeout_and_unknown_remain_distinct(self):
        import socket,ssl
        for exc,category in [(socket.gaierror(-2,'unresolved'),'DNS'),(ssl.SSLError('bad handshake'),'TLS'),(TimeoutError(),'TIMEOUT'),(RuntimeError('private response text'),'UNKNOWN')]:
            self.assertEqual(monitor.error_info(exc).category,category)
        self.assertFalse(monitor.error_info(ssl.SSLError()).retryable)
        self.assertNotIn('private response text',json.dumps(monitor.error_info(RuntimeError('private response text')).as_dict()))

    def test_html_challenge_soft404_and_js_shell_not_source_text(self):
        samples=[(b'<title>Just a moment</title><p>Verify you are human</p>','BLOCKED'),
                 (b'<h1>Page not found</h1>','NOT_FOUND'),
                 (b'<div id="root"></div><script src="/app.js"></script>','PARSER_ERROR')]
        for body,category in samples:
            with self.subTest(category=category),self.assertRaises(monitor.MonitorError) as ctx:monitor.extract(body,'text/html')
            self.assertEqual(ctx.exception.category,category)
        challenge=monitor.MonitorError('BLOCKED','CHALLENGE_PAGE','Human verification.',200)
        with patch('monitor.fetch_once',side_effect=challenge) as fetch,patch('monitor.time.sleep') as sleep:
            with self.assertRaises(monitor.MonitorError):monitor.fetch_text(URL,self.config)
            self.assertEqual(fetch.call_count,1);sleep.assert_not_called()

    def test_recovery_clears_active_error_preserves_history_hash_and_review(self):
        with workspace_temp() as td:
            events=[];root=Path(td)
            first=monitor.observe(URL,'Rule text',{'reviewRequired':True},root,'t1',events)
            failure=monitor.failed(URL,first,'t2',monitor.http_error(403).as_dict())
            self.assertEqual(failure['lastSuccessAt'],'t1');self.assertEqual(failure['hash'],first['hash'])
            success=monitor.observe(URL,'Rule text',failure,root,'t3',events)
            self.assertEqual(success['status'],'UNCHANGED');self.assertTrue(success['reviewRequired'])
            for field in ('error','errorCode','errorCategory','detail','nextAction'):self.assertNotIn(field,success)
            self.assertEqual(success['errorHistory'][0]['errorCode'],'HTTP_403')
            self.assertEqual(len(events),1)

    def test_child_structured_error_survives_nonzero_exit(self):
        from types import SimpleNamespace
        result=monitor.http_error(404).as_dict()
        with patch('monitor.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout=json.dumps(result),stderr='do not leak')):
            observed=monitor.worker(URL,monitor.time.monotonic()+100)
            self.assertEqual(observed,result)
        with patch('monitor.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='private body')):
            observed=monitor.worker(URL,monitor.time.monotonic()+100)
            self.assertEqual(observed['errorCategory'],'INTERNAL');self.assertNotIn('private body',json.dumps(observed))

    def test_request_header_and_size_redirect_policy(self):
        from unittest.mock import Mock
        response=Mock(status=200);response.getheader.side_effect=lambda name,default=None:{'Content-Type':'text/plain','Content-Length':'100000000'}.get(name,default)
        connection=Mock();connection.getresponse.return_value=response
        with patch('monitor.PinnedHTTPS',return_value=connection),patch('monitor.resolve_public',return_value='8.8.8.8'),patch('monitor.host_throttle.wait'):
            with self.assertRaises(monitor.MonitorError) as ctx:monitor.fetch_text(URL,self.config)
            self.assertEqual(ctx.exception.code,'BODY_LIMIT')
            headers=connection.request.call_args.kwargs['headers']
            self.assertIn('CourtScanSourceMonitor',headers['User-Agent'])
            self.assertEqual(headers['Accept-Encoding'],'identity')
            response.read.assert_not_called()
        response.status=302;response.getheader.side_effect=lambda name,default=None:'http://court.example/insecure' if name=='Location' else default
        with patch('monitor.PinnedHTTPS',return_value=connection),patch('monitor.resolve_public',return_value='8.8.8.8'),patch('monitor.host_throttle.wait'):
            with self.assertRaises(monitor.MonitorError) as ctx:monitor.fetch_text(URL,self.config)
            self.assertEqual(ctx.exception.code,'REDIRECT_DENIED')

    def test_exact_replacement_only_and_manual_review(self):
        target='https://court.example/new'
        config={**self.config,'sourceReplacements':{URL:{'url':target,'verifiedAt':'2026-11-01','evidenceUrl':target}}}
        with patch('monitor.fetch_once',return_value={'text':'New rule','resolvedUrl':target}) as fetch:
            result=monitor.fetch_text(URL,config)
            self.assertEqual(fetch.call_args.args[0],target)
            self.assertTrue(result['reviewRequired']);self.assertTrue(result['observedSourceChange'])
        with self.assertRaises(ValueError):monitor.fetch_text(target,config)
        config['sourceReplacements'][URL]['url']='https://evil.example/new'
        with patch('monitor.fetch_once') as fetch:
            with self.assertRaises(ValueError):monitor.fetch_text(URL,config)
            fetch.assert_not_called()

    def docx(self,parts=None):
        import io,zipfile
        contents={'[Content_Types].xml':'<Types><Override ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
                  'word/document.xml':'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Legal rule</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Table condition</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>',
                  'word/footnotes.xml':'<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:footnote><w:p><w:r><w:t>Footnote condition</w:t></w:r></w:p></w:footnote></w:footnotes>'}
        contents.update(parts or {})
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            for name,value in contents.items():z.writestr(name,value)
        return stream.getvalue()

    def test_docx_tables_notes_and_review(self):
        metadata={}
        result=monitor.extract(self.docx(),'application/vnd.openxmlformats-officedocument.wordprocessingml.document',metadata=metadata)
        for text in ('Legal rule','Table condition','Footnote condition'):self.assertIn(text,result)
        self.assertEqual(metadata['extractionMethod'],'DOCX_TEXT');self.assertTrue(metadata['reviewRequired'])

    def test_docx_entities_macro_and_expansion_limits(self):
        for parts,code in [({'word/document.xml':'<!DOCTYPE x [<!ENTITY a "secret">]><x>&a;</x>'},'DOCX_XML_ENTITIES'),
                           ({'word/vbaProject.bin':'macro'},'DOCX_MACROS'),
                           ({'../external.xml':'x'},'DOCX_UNSAFE_PART'),
                           ({'extra'+str(i):'' for i in range(513)},'DOCX_EXPANSION_LIMIT')]:
            with self.subTest(code=code),self.assertRaises(monitor.MonitorError) as ctx:monitor.extract(self.docx(parts),'application/octet-stream')
            self.assertEqual(ctx.exception.code,code)

    def test_pdf_strict_and_real_password_still_rejected(self):
        import io
        from pypdf import PdfWriter
        stream=io.BytesIO();writer=PdfWriter();writer.add_blank_page(width=100,height=100);writer.encrypt('secret');writer.write(stream)
        with self.assertRaises(monitor.MonitorError) as ctx:monitor.extract(stream.getvalue(),'application/pdf')
        self.assertEqual(ctx.exception.code,'PDF_ENCRYPTED')
        with self.assertRaises(monitor.MonitorError) as ctx:monitor.extract(b'%PDF-1.7\nbroken','application/pdf')
        self.assertEqual(ctx.exception.code,'PDF_PARSE_ERROR')

    def test_ocr_missing_tools_and_page_limit_are_explicit(self):
        import bounded_ocr
        with patch('bounded_ocr.shutil.which',return_value=None):
            with self.assertRaises(bounded_ocr.OCRFailure) as ctx:bounded_ocr.extract_pdf(b'pdf',1,monitor.time.monotonic()+20,100)
            self.assertEqual(ctx.exception.code,'OCR_UNAVAILABLE')
            with self.assertRaises(bounded_ocr.OCRFailure) as ctx:bounded_ocr.extract_pdf(b'pdf',21,monitor.time.monotonic()+20,100)
            self.assertEqual(ctx.exception.category,'LIMIT')

    def test_ocr_processes_all_pages_and_keeps_review_metadata(self):
        import bounded_ocr
        from types import SimpleNamespace
        header='level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tconf\ttext\n'
        rows=''.join('5\t1\t1\t1\t1\t%d\t90\tword%d\n'%(i,i) for i in range(1,13))
        calls=[]
        def execute(args,**kwargs):
            calls.append(args)
            self.assertGreater(kwargs['timeout'],0)
            self.assertEqual(kwargs['env']['OMP_THREAD_LIMIT'],'1')
            if args[0]=='pdftoppm':
                Path(args[-1]+'.png').write_bytes(b'image')
                return SimpleNamespace(returncode=0,stdout=b'')
            return SimpleNamespace(returncode=0,stdout=(header+rows).encode())
        with workspace_temp() as td,patch('bounded_ocr.shutil.which',side_effect=lambda name:name),patch('bounded_ocr.subprocess.run',side_effect=execute),patch('bounded_ocr.tempfile.TemporaryDirectory',return_value=workspace_temp()):
            text,meta=bounded_ocr.extract_pdf(b'pdf',2,monitor.time.monotonic()+20,10000)
        self.assertEqual(len(calls),4);self.assertEqual(meta['ocrPages'],2)
        self.assertTrue(meta['reviewRequired']);self.assertEqual(meta['extractionMethod'],'OCR')
        self.assertEqual(meta['ocrMeanConfidence'],90);self.assertEqual(meta['ocrEmptyPages'],[])
        self.assertIn('word12',text)

    def test_host_throttle_shares_server_cooldown(self):
        import host_throttle,os
        with workspace_temp() as td,patch.dict(os.environ,{'COURTSCAN_THROTTLE_DIR':str(td)}):
            host_throttle.defer('court.example',30,monitor.time.monotonic()+5)
            with self.assertRaises(TimeoutError):host_throttle.wait('court.example',monitor.time.monotonic()+1)
            host_throttle.wait('other.example',monitor.time.monotonic()+1)

    def test_partial_ocr_is_error_not_success(self):
        import bounded_ocr
        from types import SimpleNamespace
        header='level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tconf\ttext\n'
        rows=''.join('5\t1\t1\t1\t1\t%d\t90\tword%d\n'%(i,i) for i in range(1,13))
        tesseract_calls=[]
        def execute(args,**kwargs):
            if args[0]=='pdftoppm':
                Path(args[-1]+'.png').write_bytes(b'image')
                return SimpleNamespace(returncode=0,stdout=b'')
            tesseract_calls.append(args)
            return SimpleNamespace(returncode=0,stdout=(header+(rows if len(tesseract_calls)==1 else '')).encode())
        with patch('bounded_ocr.shutil.which',side_effect=lambda name:name),patch('bounded_ocr.subprocess.run',side_effect=execute),patch('bounded_ocr.tempfile.TemporaryDirectory',return_value=workspace_temp()):
            with self.assertRaises(bounded_ocr.OCRFailure) as ctx:bounded_ocr.extract_pdf(b'pdf',2,monitor.time.monotonic()+20,10000)
        self.assertEqual(ctx.exception.code,'OCR_INCOMPLETE')

    def test_mixed_pdf_keeps_native_text_and_requires_missing_page_ocr(self):
        import io
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject,NameObject,DecodedStreamObject
        writer=PdfWriter()
        first=writer.add_blank_page(width=300,height=300)
        font=DictionaryObject({NameObject('/Type'):NameObject('/Font'),NameObject('/Subtype'):NameObject('/Type1'),NameObject('/BaseFont'):NameObject('/Helvetica')})
        first[NameObject('/Resources')]=DictionaryObject({NameObject('/Font'):DictionaryObject({NameObject('/F1'):font})})
        content=DecodedStreamObject();content.set_data(b'BT /F1 12 Tf 20 200 Td (A legal rule on the text page.) Tj ET')
        first[NameObject('/Contents')]=content
        second=writer.add_blank_page(width=300,height=300)
        graphics=DecodedStreamObject();graphics.set_data(b'q 1 0 0 1 0 0 cm Q')
        second[NameObject('/Contents')]=graphics
        stream=io.BytesIO();writer.write(stream)
        with patch('monitor.bounded_ocr.extract_pdf',side_effect=monitor.bounded_ocr.OCRFailure('OCR_INCOMPLETE','Second page unreadable')) as ocr:
            with self.assertRaises(monitor.MonitorError) as ctx:monitor.extract(stream.getvalue(),'application/pdf')
            self.assertEqual(ctx.exception.code,'OCR_INCOMPLETE')
            self.assertEqual(ocr.call_args.args[1],2)
            self.assertIn('A legal rule on the text page.',ocr.call_args.kwargs['native_texts'][0])
            self.assertEqual(ocr.call_args.kwargs['native_texts'][1],'')

    def test_docx_utf16_entity_declaration_is_rejected(self):
        hostile='<!DOCTYPE x [<!ENTITY a "secret">]><x>&a;</x>'.encode('utf-16')
        with self.assertRaises(monitor.MonitorError) as ctx:monitor.extract(self.docx({'word/document.xml':hostile}),'application/octet-stream')
        self.assertEqual(ctx.exception.code,'DOCX_XML_ENTITIES')

    def test_sync_ocr_sets_manual_review_and_keeps_rights_policy(self):
        with workspace_temp() as root:
            data=root/'data';data.mkdir()
            monitor.atomic_json(root/'allowlist.json',{**self.config,'skipped':[],'publicTextUrls':[]})
            monitor.atomic_json(data/'court-rules.min.json',{'records':[{'id':'r','sourceUrl':URL,'verificationLabel':'PRIMARY_SOURCE_REVIEWED','actionProfile':{'generationEligible':True}}],'counts':{}})
            monitor.atomic_json(data/'source-status.json',{'sources':[],'preparedAt':'2026-10-31T00:00:00Z','limitations':['No live monitor run has been performed for this initial package.','No OCR: scanned PDFs remain ERROR.']})
            monitor.atomic_json(data/'changelog.json',{'events':[]})
            result={'text':'OCR legal text','resolvedUrl':URL,'observedAt':'2026-11-01T00:00:00Z','attempts':1,'httpStatus':200,'extractionMethod':'OCR','reviewRequired':True,'ocrPages':1,'ocrMeanConfidence':95,'ocrEmptyPages':[]}
            with patch('monitor.worker',return_value=result):self.assertEqual(monitor.sync(root),0)
            status=json.loads((data/'source-status.json').read_text())
            source=status['sources'][0]
            self.assertEqual(status['preparedAt'],'2026-10-31T00:00:00Z')
            self.assertNotIn('No live monitor run',json.dumps(status['limitations']))
            self.assertNotIn('No OCR:',json.dumps(status['limitations']))
            self.assertTrue(any('Two-day' in value for value in status['limitations']))
            self.assertTrue(any('hash-only' in value for value in status['limitations']))
            record=json.loads((data/'court-rules.min.json').read_text())['records'][0]
            self.assertTrue(source['reviewRequired']);self.assertEqual(source['extractionMethod'],'OCR')
            self.assertEqual(source['textPublication'],'HASH_ONLY');self.assertIsNone(source['snapshot'])
            self.assertEqual(record['verificationLabel'],'REVIEW_REQUIRED')
            self.assertFalse(record['actionProfile']['generationEligible'])
            self.assertFalse(list(root.rglob('*.txt')))


    def test_selective_ocr_keeps_native_text_and_document_page_order(self):
        import bounded_ocr
        from types import SimpleNamespace
        native=['Native page '+str(page) for page in range(1,26)]
        native[1]='';native[14]='';native[23]=''
        selected=[];active=[]
        header='level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tconf\ttext\n'
        def execute(args,**kwargs):
            if args[0]=='pdftoppm':
                page=int(args[args.index('-f')+1]);selected.append(page);active[:]=[page]
                self.assertEqual(args[args.index('-l')+1],str(page))
                Path(args[-1]+'.png').write_bytes(b'image')
                return SimpleNamespace(returncode=0,stdout=b'')
            rows=''.join('5\t1\t1\t1\t1\t%d\t90\tpage%dword%d\n'%(i,active[0],i) for i in range(1,13))
            return SimpleNamespace(returncode=0,stdout=(header+rows).encode())
        with patch('bounded_ocr.shutil.which',side_effect=lambda name:name),patch('bounded_ocr.subprocess.run',side_effect=execute),patch('bounded_ocr.tempfile.TemporaryDirectory',return_value=workspace_temp()):
            text,metadata=bounded_ocr.extract_pdf(b'pdf',25,monitor.time.monotonic()+20,10000,blank_pages=[15],native_texts=native)
        self.assertEqual(selected,[2,24])
        expected=list(native)
        for page in selected:expected[page-1]=' '.join('page%dword%d'%(page,i) for i in range(1,13))
        self.assertEqual(text,'\n'.join(expected))
        self.assertEqual(metadata['pdfPages'],25);self.assertEqual(metadata['ocrPages'],2)
        self.assertEqual(metadata['ocrPageNumbers'],[2,24]);self.assertEqual(metadata['blankPdfPageNumbers'],[15])
        self.assertEqual(sorted(metadata['ocrPageNumbers']+metadata['nativeTextPageNumbers']+metadata['blankPdfPageNumbers']),list(range(1,26)))
        self.assertTrue(metadata['reviewRequired'])

    def test_selective_ocr_still_rejects_more_than_twenty_missing_pages(self):
        import bounded_ocr
        with patch('bounded_ocr.shutil.which') as tool:
            with self.assertRaises(bounded_ocr.OCRFailure) as ctx:
                bounded_ocr.extract_pdf(b'pdf',25,monitor.time.monotonic()+20,10000,native_texts=['Native']*4+['']*21)
            self.assertEqual(ctx.exception.code,'OCR_PAGE_LIMIT');tool.assert_not_called()
            with self.assertRaises(bounded_ocr.OCRFailure) as ctx:
                bounded_ocr.extract_pdf(b'pdf',501,monitor.time.monotonic()+20,10000,native_texts=['Native']*500+[''])
            self.assertEqual(ctx.exception.code,'PDF_PAGE_LIMIT')

    def test_selective_ocr_cannot_drop_unaccounted_pages(self):
        import bounded_ocr
        for texts,blank in [(['native'],[]),(['native',''],[1]),(['native',''],[3])]:
            with self.subTest(texts=texts,blank=blank),self.assertRaises(bounded_ocr.OCRFailure) as ctx:
                bounded_ocr.extract_pdf(b'pdf',2,monitor.time.monotonic()+20,1000,blank_pages=blank,native_texts=texts)
            self.assertEqual(ctx.exception.code,'OCR_PAGE_ACCOUNTING')

    def test_selective_ocr_missing_page_failure_discards_combined_result(self):
        import bounded_ocr
        from types import SimpleNamespace
        header='level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tconf\ttext\n'
        native=['Native page '+str(p) for p in range(1,26)];native[1]='';native[23]=''
        active=[]
        def execute(args,**kwargs):
            if args[0]=='pdftoppm':
                active[:]=[int(args[args.index('-f')+1])]
                Path(args[-1]+'.png').write_bytes(b'image')
                return SimpleNamespace(returncode=0,stdout=b'')
            rows=''.join('5\t1\t1\t1\t1\t%d\t90\tword%d\n'%(i,i) for i in range(1,13)) if active[0]==2 else ''
            return SimpleNamespace(returncode=0,stdout=(header+rows).encode())
        with patch('bounded_ocr.shutil.which',side_effect=lambda name:name),patch('bounded_ocr.subprocess.run',side_effect=execute),patch('bounded_ocr.tempfile.TemporaryDirectory',return_value=workspace_temp()):
            with self.assertRaises(bounded_ocr.OCRFailure) as ctx:
                bounded_ocr.extract_pdf(b'pdf',25,monitor.time.monotonic()+20,10000,native_texts=native)
        self.assertEqual(ctx.exception.code,'OCR_INCOMPLETE')

    def test_network_wait_is_longer_but_deadline_bounded(self):
        from unittest.mock import Mock
        for remaining,expected in [(80,25),(7,7)]:
            response=Mock(status=200)
            response.getheader.side_effect=lambda name,default=None:{'Content-Type':'text/plain','Content-Length':'10'}.get(name,default)
            response.read.side_effect=[b'Legal rule',b'']
            connection=Mock();connection.getresponse.return_value=response
            with patch('monitor.PinnedHTTPS',return_value=connection) as factory,patch('monitor.resolve_public',return_value='8.8.8.8'),patch('monitor.host_throttle.wait'),patch('monitor.time.monotonic',return_value=100):
                result=monitor.fetch_once(URL,self.config,100+remaining)
            self.assertEqual(result['text'],'Legal rule')
            self.assertEqual(factory.call_args.args[2],expected)
            self.assertTrue(all(call.args[0]<=expected for call in connection.sock.settimeout.call_args_list))
        self.assertEqual(monitor.SOURCE_SECONDS,90);self.assertEqual(monitor.RUN_SECONDS,720)


    def api_fixture(self):
        identity='3e4e42a0-7045-4e32-432f-08de214ff94e'
        adapter={'type':'CACD_JUDGE_PROCEDURES','judgeId':identity,'initials':'DSR','blockTitle':'Important Notice'}
        url='https://apps.cacd.uscourts.gov/JpsApi/judge/'+identity
        source='https://apps.cacd.uscourts.gov/Jps/#/judge/'+identity+'/dsr'
        clause='Artificial Intelligence. Counsel and parties are reminded of their responsibilities when signing any document filed with this court and must comply with Federal Rule of Civil Procedure 11. This synthetic fixture also contains the entire final sentence.'
        data={'id':identity,'initials':'DSR','name':'Daniel S. Roberts','zoomPasscode':'UNRELATED_SECRET','webPage':{'webBlocks':[{'title':'Other','content':None},{'title':'Important Notice','content':'<p>'+clause+'</p>'},{'title':'Calendar','content':'UNRELATED_CALENDAR'}]}}
        return source,url,adapter,data,clause

    def test_exact_api_route_returns_whole_selected_procedure_only(self):
        from unittest.mock import Mock
        source,url,adapter,data,clause=self.api_fixture()
        body=json.dumps(data).encode()
        response=Mock(status=200)
        response.getheader.side_effect=lambda name,default=None:{'Content-Type':'application/json','Content-Length':str(len(body))}.get(name,default)
        response.read.side_effect=[body,b'']
        connection=Mock();connection.getresponse.return_value=response
        config={'urls':[source],'hosts':['apps.cacd.uscourts.gov'],'sourceReplacements':{source:{'url':url,'verifiedAt':'2026-11-01','evidenceUrl':source,'note':'fixture','adapter':adapter}}}
        with patch('monitor.PinnedHTTPS',return_value=connection),patch('monitor.resolve_public',return_value='8.8.8.8'),patch('monitor.host_throttle.wait'):
            result=monitor.fetch_text(source,config)
        self.assertEqual(result['resolvedUrl'],url)
        self.assertEqual(result['text'],'Judge: Daniel S. Roberts (DSR)\nImportant Notice\n'+clause)
        self.assertNotIn('UNRELATED',result['text'])
        self.assertEqual(result['extractionMethod'],'CACD_PROCEDURE_HTML')
        self.assertTrue(result['reviewRequired']);self.assertTrue(result['observedSourceChange'])

    def test_api_identity_schema_and_exact_block_fail_closed(self):
        source,url,adapter,data,clause=self.api_fixture()
        variants=[]
        changed=copy.deepcopy(data);changed['id']='other';variants.append((changed,'ADAPTER_IDENTITY'))
        changed=copy.deepcopy(data);changed['name']='Other Judge';variants.append((changed,'ADAPTER_IDENTITY'))
        changed=copy.deepcopy(data);changed['initials']='OTHER';variants.append((changed,'ADAPTER_IDENTITY'))
        changed=copy.deepcopy(data);changed['webPage']=None;variants.append((changed,'ADAPTER_SCHEMA'))
        changed=copy.deepcopy(data);changed['webPage']['webBlocks']={};variants.append((changed,'ADAPTER_SCHEMA'))
        changed=copy.deepcopy(data);changed['webPage']['webBlocks']=[];variants.append((changed,'ADAPTER_BLOCK'))
        changed=copy.deepcopy(data);changed['webPage']['webBlocks'].append(changed['webPage']['webBlocks'][1]);variants.append((changed,'ADAPTER_BLOCK'))
        for content in (None,'',13):
            changed=copy.deepcopy(data);changed['webPage']['webBlocks'][1]['content']=content;variants.append((changed,'ADAPTER_EMPTY_BLOCK'))
        for changed,code in variants:
            with self.subTest(code=code),self.assertRaises(monitor.cacd_adapter.AdapterError) as ctx:
                monitor.cacd_adapter.read_html(json.dumps(changed).encode(),'application/json',adapter,url)
            self.assertEqual(ctx.exception.code,code)

    def test_api_scope_rejects_unknown_url_and_mismatched_original_identity(self):
        source,url,adapter,data,clause=self.api_fixture()
        for target in (url+'?other=1',url+'/',url.replace('https:','http:'),url.replace('apps.cacd.uscourts.gov','evil.example')):
            with self.subTest(target=target),self.assertRaises(monitor.cacd_adapter.AdapterError):
                monitor.cacd_adapter.validate(adapter,target,source)
        with self.assertRaises(monitor.cacd_adapter.AdapterError):
            monitor.cacd_adapter.validate(adapter,url,source.replace('/dsr','/ayp'))
        changed={**adapter,'judgeId':'00000000-0000-0000-0000-000000000000'}
        with self.assertRaises(monitor.cacd_adapter.AdapterError):monitor.cacd_adapter.validate(changed,url)

    def test_api_missing_ai_body_and_non_json_never_success(self):
        source,url,adapter,data,clause=self.api_fixture()
        for text in ('Artificial Intelligence','Artificial Intelligence\nRule 11','Ordinary procedures with no selected legal section.'*8):
            with self.subTest(text=text),self.assertRaises(monitor.cacd_adapter.AdapterError) as ctx:monitor.cacd_adapter.verify_text(text)
            self.assertEqual(ctx.exception.code,'ADAPTER_AI_BODY_MISSING')
        for body,kind,code in [(b'<html><div id="root"></div></html>','text/html','ADAPTER_CONTENT_TYPE'),(b'{}','application/json','ADAPTER_IDENTITY'),(b'{"id":1,"id":2}','application/json','ADAPTER_DUPLICATE_KEY'),(b'not json','application/json','ADAPTER_JSON'),(b'x'*(1024*1024+1),'application/json','ADAPTER_BODY_LIMIT')]:
            with self.subTest(code=code),self.assertRaises(monitor.cacd_adapter.AdapterError) as ctx:monitor.cacd_adapter.read_html(body,kind,adapter,url)
            self.assertEqual(ctx.exception.code,code)

    def test_api_redirect_requires_renewed_review(self):
        from unittest.mock import Mock
        source,url,adapter,data,clause=self.api_fixture()
        response=Mock(status=302)
        connection=Mock();connection.getresponse.return_value=response
        with patch('monitor.PinnedHTTPS',return_value=connection),patch('monitor.resolve_public',return_value='8.8.8.8'),patch('monitor.host_throttle.wait'):
            with self.assertRaises(monitor.MonitorError) as ctx:
                monitor.fetch_once(url,{'hosts':['apps.cacd.uscourts.gov']},monitor.time.monotonic()+20,adapter=adapter)
        self.assertEqual(ctx.exception.code,'ADAPTER_REDIRECT_DENIED')

if __name__=='__main__':unittest.main()
