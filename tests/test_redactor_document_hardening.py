"""Real public-document/engine tests plus explicitly controlled option-contract tests.

No real client matters. The PDF is an unchanged first-two-page excerpt of the
repository's public prospectus, not a made-up document or an accuracy benchmark.
"""
import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import documentreview as docs, redactionmodel, releaseflow, ocr
from app.web import AppState, create_redactor_app
from tests.smoke._helpers import _clear_prepared_test_jobs


class OptionTests(unittest.TestCase):
    def test_unsupported_options_and_terms_are_not_silently_dropped(self):
        cap={'locales':['sg'],'profiles':[],'disable_builtins':['email'],
             'boolean_options':['context'],'limits':{'terms':2,'term_bytes':4}}
        for options in [{'unknown':True},{'locales':['unknown']},{'terms':['longer']},
                        {'terms':['a','b','c']},{'context':'true'},{'terms':['']}]:
            with self.subTest(options=options),patch.object(docs,'capabilities',return_value=cap):
                with self.assertRaises(ValueError):docs.checked_options(options)

    def test_name_expansion_survives_host_bridge(self):
        self.assertTrue(redactionmodel.normalize_options({'name_expansion':True})['name_expansion'])

    def test_invalid_capability_limits_are_refused(self):
        for limit in [None,True,'100',0,-1]:
            with patch.object(redactionmodel,'_run',return_value={'op':'capabilities','contract_version':1,
                     'locales':[],'profiles':[],'disable_builtins':[],'boolean_options':[],
                     'limits':{'terms':limit,'term_bytes':200}}):
                with self.assertRaises(ValueError):docs.capabilities()


@unittest.skipUnless(redactionmodel.available() and ocr.available(), 'actual engine and Tesseract required for public-document integration')
class PublicDocumentTests(unittest.TestCase):
    def setUp(self):
        import fitz
        self.temp=tempfile.TemporaryDirectory()
        self.env=patch.dict(os.environ,{'LAWDATAMAN_DATA_DIR':self.temp.name,'LAWDATAMAN_DISABLE_OS_OPEN':'1'})
        self.env.start();_clear_prepared_test_jobs()
        self.original=Path(__file__).resolve().parent/'bgf-singapore-prospectus-sg.pdf'
        self.original_hash=hashlib.sha256(self.original.read_bytes()).hexdigest()
        with fitz.open(self.original) as src,fitz.open() as excerpt:
            excerpt.insert_pdf(src,from_page=0,to_page=1);self.raw=excerpt.tobytes()
        self.options={'terms':['BLACKROCK'],'disable_builtins':docs.capabilities()['disable_builtins']}
        self.plan=docs.scan_document(self.raw,'public-prospectus-excerpt.pdf',self.options)
        state=AppState();self.client=TestClient(create_redactor_app(state));self.client.headers['X-DRR-Token']=state.token

    def tearDown(self):
        self.assertEqual(hashlib.sha256(self.original.read_bytes()).hexdigest(),self.original_hash)
        _clear_prepared_test_jobs();self.env.stop();self.temp.cleanup()

    def prepare(self,selected=None,pages=None):
        return self.client.post('/api/redaction/document-prepare',json={'review_id':self.plan['review_id'],
            'accepted':selected if selected is not None else [c['id'] for c in self.plan['candidates']],
            'reviewed_pages':pages if pages is not None else [1,2]})

    def test_text_and_vector_logo_findings_share_one_immutable_plan(self):
        self.assertTrue(self.plan['pages'][0]['has_vectors'])
        self.assertEqual(self.plan['pages'][1]['processing'],'native text')
        self.assertEqual({c['surface'] for c in self.plan['candidates']},{'text','image'})
        self.assertTrue(any(c['surface']=='image' and c['page']==1 for c in self.plan['candidates']))

    def test_unknown_duplicate_ids_and_unreviewed_pages_are_refused(self):
        valid=self.plan['candidates'][0]['id']
        for selected,pages in [(['text:999999'],[1,2]),([valid,valid],[1,2]),([valid],[1]),([],[1,2])]:
            self.assertEqual(self.prepare(selected,pages).status_code,400)

    def test_engine_change_invalidates_approval(self):
        with patch.object(docs,'_engine_hash',return_value='different engine identity'):
            self.assertEqual(self.prepare().status_code,400)

    def test_residual_vector_logo_blocks_release_when_only_native_text_is_selected(self):
        selected=[c['id'] for c in self.plan['candidates'] if c['surface']=='text']
        p=self.prepare(selected).json()
        self.assertFalse(p['release_allowed'])
        self.assertTrue(any('residual' in x.lower() for x in p['blocked_reasons']))
        r=self.client.post('/api/redaction/release',json={'preparation_id':p['preparation_id'],'inspected':True,
              'exception_reason':'This cannot override a recovered logo.'})
        self.assertEqual(r.status_code,409)

    def test_actual_prepare_inspect_release_checks_different_layers_and_preserves_native_page(self):
        import fitz
        p=self.prepare().json();self.assertTrue(p['release_allowed']);self.assertTrue(p['exception_required'])
        self.assertFalse(list((Path(self.temp.name)/'exports').glob('*')))
        job=releaseflow._JOBS[p['preparation_id']];name=job['documents'][0];raw=(job['directory']/name).read_bytes()
        with fitz.open(stream=raw,filetype='pdf') as doc:
            self.assertEqual(len(doc),2)
            self.assertFalse(doc[0].get_text().strip())
            self.assertIn('INNOVATION FUND',doc[1].get_text())
            self.assertNotIn('blackrock',doc[1].get_text().casefold())
            self.assertEqual(doc.embfile_count(),0)
        report=json.loads((job['directory']/(name+'.report.json')).read_text())
        self.assertEqual(report['verification']['image_recovery']['possible_hits'],0)
        self.assertEqual(report['verification']['image_recovery']['pages_checked'],1)
        self.assertEqual(report['review_binding']['source_sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertNotIn('BLACKROCK',json.dumps(report))
        preview=self.client.post('/api/redaction/prepared-preview',json={'preparation_id':p['preparation_id'],'filename':name,'page':1})
        self.assertEqual(preview.status_code,200);self.assertTrue(preview.json()['image'])
        released=self.client.post('/api/redaction/release',json={'preparation_id':p['preparation_id'],'inspected':True,
              'exception_reason':'Public excerpt engineering test only; unknown content and unprobed surfaces remain outside this test.'})
        self.assertEqual(released.status_code,200)
        self.assertTrue((Path(self.temp.name)/'exports'/released.json()['filename']).is_file())

if __name__=='__main__':unittest.main()
