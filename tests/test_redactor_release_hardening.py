"""Publication boundary regressions. Controlled records are NOT PDF accuracy evidence."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app import releaseflow as flow
from app.paths import data_dir, exports_dir
from app.web import AppState, create_app, create_redactor_app
from tests.smoke._helpers import _clear_prepared_test_jobs


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"LAWDATAMAN_DATA_DIR": self.temp.name,
                                          "LAWDATAMAN_DISABLE_OS_OPEN": "1"})
        self.env.start()
        _clear_prepared_test_jobs()

    def tearDown(self):
        _clear_prepared_test_jobs()
        self.env.stop()
        self.temp.cleanup()

    def prepare(self, state="no_residuals_detected", *, missing_report=False,
                unresolved=False, rust_status="completed", key=False, bad_hash=False):
        @flow.prepare_export
        def writer():
            raw = b"[REMOVED] controlled publication test"
            digest = hashlib.sha256(raw).hexdigest()
            path = exports_dir() / "document.txt"
            path.write_bytes(raw)
            report = {"output": {"sha256": digest}, "could_not_remove": 0,
                      "verification": {"artifact_sha256": "bad" if bad_hash else digest,
                      "state": state, "coverage": {"complete": not unresolved, "requested": 1,
                      "resolved": 0 if unresolved else 1, "unresolved": 1 if unresolved else 0},
                      "reasons": [], "rust": {"status": rust_status,"artifact_sha256":digest}},
                      "not_removed": []}
            if not missing_report:
                (path.parent / "document.txt.report.json").write_text(json.dumps(report))
                (path.parent / "document.txt.report.txt").write_text("Controlled report test")
            if key:
                (path.parent / "document.labelkey.txt").write_text("PRIVATE_TEST_KEY")
            return JSONResponse({"ok":True,"filename":"document.txt",
                                 "report_filename":"document.txt.report.json",
                                 "report_txt_filename":"document.txt.report.txt",
                                 "key_filename":"document.labelkey.txt" if key else None})
        result=writer()
        self.assertEqual(result.status_code,200)
        result=json.loads(result.body)
        self.assertTrue(result["prepared"])
        self.assertNotIn("filename",result)
        self.assertFalse(list((data_dir()/"exports").glob("release-*")))
        return result

    def release(self, prepared, **kwargs):
        return flow.release(prepared['preparation_id'],kwargs.get('inspected',True),
                            kwargs.get('exception_reason',''))

    def test_prepare_does_not_publish_and_suppresses_os_open(self):
        from app import osio
        seen=[]
        @flow.prepare_export
        def writer():
            seen.append(osio._disabled())
            return JSONResponse({"error":"controlled error"},status_code=400)
        writer()
        self.assertEqual(seen,[True])
        self.assertIsNone(flow.STAGE_DIRECTORY.get())
        self.assertEqual(flow._JOBS,{})

    def test_release_requires_attestation_and_publishes_document_and_reports_together(self):
        p=self.prepare()
        with self.assertRaises(ValueError):self.release(p,inspected=False)
        result=self.release(p)
        directory=data_dir()/"exports"/result["release_package"]
        self.assertEqual({x.name for x in directory.iterdir()},
            {"document.txt","document.txt.report.json","document.txt.report.txt","release-receipt.json"})
        receipt=json.loads((directory/"release-receipt.json").read_text())
        for name,record in receipt["files"].items():
            self.assertEqual(hashlib.sha256((directory/name).read_bytes()).hexdigest(),record["sha256"])
        with self.assertRaises(ValueError):self.release(p)

    def test_residual_cannot_be_overridden_by_exception(self):
        p=self.prepare('residuals_possible')
        self.assertFalse(p['release_allowed'])
        with self.assertRaises(ValueError):self.release(p,exception_reason='A long arbitrary explanation cannot override a recovered target.')

    def test_unavailable_engine_cannot_be_overridden(self):
        p=self.prepare('could_not_fully_verify',rust_status='unavailable')
        with self.assertRaises(ValueError):self.release(p,exception_reason='An unavailable verification engine cannot be bypassed.')

    def test_missing_report_blocks(self):
        p=self.prepare(missing_report=True)
        with self.assertRaises(ValueError):self.release(p)

    def test_unresolved_target_blocks(self):
        p=self.prepare(unresolved=True)
        with self.assertRaises(ValueError):self.release(p,exception_reason='Cannot override missing source decisions.')

    def test_unbound_report_blocks(self):
        p=self.prepare(bad_hash=True)
        with self.assertRaises(ValueError):self.release(p)

    def test_incomplete_coverage_requires_recorded_specific_exception(self):
        p=self.prepare('could_not_fully_verify')
        with self.assertRaises(ValueError):self.release(p)
        note='Controlled workflow test only: known unprobed surface accepted explicitly.'
        result=self.release(p,exception_reason=note)
        receipt=json.loads((data_dir()/"exports"/result['release_receipt']).read_text())
        self.assertEqual(receipt['manual_exception'],note)

    def test_changed_document_invalidates_release(self):
        p=self.prepare();job=flow._JOBS[p['preparation_id']]
        (job['directory']/'document.txt').write_text('Changed bytes')
        with self.assertRaises(ValueError):self.release(p)
        self.assertFalse(list((data_dir()/'exports').glob('release-*')))

    def test_added_file_and_changed_report_invalidate_release(self):
        for name in ['unexpected.txt','document.txt.report.json']:
            p=self.prepare();job=flow._JOBS[p['preparation_id']]
            (job['directory']/name).write_text('Changed bytes')
            with self.assertRaises(ValueError):self.release(p)

    def test_keys_remain_separate(self):
        p=self.prepare(key=True);result=self.release(p)
        directory=data_dir()/'exports'/result['release_package']
        self.assertTrue(result['key_retained_separately'])
        self.assertIsNone(result['key_filename'])
        self.assertTrue((data_dir()/'reidentification-keys'/result['key_reference']/'document.labelkey.txt').is_file())
        self.assertNotIn('PRIVATE_TEST_KEY', ''.join(x.read_text() for x in directory.iterdir()))
        self.assertFalse(any('key' in x.name for x in directory.iterdir()))

    def test_atomic_publish_never_replaces_existing_directory(self):
        a=data_dir()/'a';b=data_dir()/'b';a.mkdir();b.mkdir();(b/'keep').write_text('original')
        with self.assertRaises(OSError):flow.rename_no_replace(a,b)
        self.assertEqual((b/'keep').read_text(),'original')
        self.assertTrue(a.exists())

    def test_failed_atomic_publish_leaves_no_partial_export_and_can_retry(self):
        p=self.prepare(key=True)
        with patch.object(flow,'rename_no_replace',side_effect=OSError('controlled failure')):
            with self.assertRaises(OSError):self.release(p)
        self.assertFalse(list((data_dir()/'exports').glob('*')))
        self.assertFalse(list(data_dir().glob('.publish-*')))
        self.assertFalse((data_dir()/'reidentification-keys'/p['preparation_id']).exists())
        self.assertTrue(self.release(p)['released'])

    def test_expired_job_cannot_be_released(self):
        p=self.prepare();flow._JOBS[p['preparation_id']]['created']-=flow.TTL_SECONDS+1
        with self.assertRaises(ValueError):self.release(p)

    def test_token_guard_and_preview_confinement(self):
        state=AppState();client=TestClient(create_redactor_app(state));p=self.prepare()
        for route in ['release','prepared-preview','discard-prepared','document-scan','document-prepare','document-page','discard-review']:
            self.assertEqual(client.post('/api/redaction/'+route,json={}).status_code,403)
        self.assertEqual(client.get('/api/redaction/capabilities').status_code,403)
        client.headers['X-DRR-Token']=state.token
        for name in ['../document.txt','document.labelkey.txt',[],None]:
            r=client.post('/api/redaction/prepared-preview',json={'preparation_id':p['preparation_id'],'filename':name})
            self.assertEqual(r.status_code,400)
        r=client.post('/api/redaction/prepared-preview',json={'preparation_id':p['preparation_id'],'filename':'document.txt'})
        self.assertEqual(r.status_code,200)
        self.assertIn('[REMOVED]',r.json()['text'])

    def test_workspace_assembles_without_remote_resources_in_both_variants(self):
        for factory in [create_app,create_redactor_app]:
            response=TestClient(factory(AppState())).get('/workspace')
            self.assertEqual(response.status_code,200)
            self.assertIn('document-prepare',response.text)
            self.assertNotIn('https://',response.text)
            self.assertNotIn('/* __WORKSPACE_JS__ */',response.text)


if __name__=='__main__':unittest.main()
