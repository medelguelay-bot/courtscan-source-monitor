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
        self.assertEqual(set(config['urls'])|set(config['skipped']),actual)
        self.assertFalse(set(config['urls']) & set(config['skipped']))

if __name__=='__main__':unittest.main()
