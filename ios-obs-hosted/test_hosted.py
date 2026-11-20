import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hosted_project',HERE/'project.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
b=p.load('hosted_binding',HERE/'binding.py')
class Hosted(unittest.TestCase):
    def test_separate_link_graph(self):
        objects=p.document()['objects']
        app=objects[p.ident(71)]['buildSettings']
        test=objects[p.ident(72)]['buildSettings']
        self.assertEqual(test['BUNDLE_LOADER'],'$(TEST_HOST)')
        self.assertIn(b.APP+'.app/'+b.APP,test['TEST_HOST'])
        self.assertIn('$(PROJECT_DIR)/Inputs/libmadcrypto_ffi.a',app['OTHER_LDFLAGS'])
        self.assertIn('$(PROJECT_DIR)/Inputs/libmadobs_runtime.a',app['OTHER_LDFLAGS'])
        self.assertNotIn('OTHER_LDFLAGS',test)
        self.assertEqual(objects[p.ident(30)]['productName'],b.APP)
        self.assertEqual(objects[p.ident(31)]['productName'],b.TEST)
        tree=ET.fromstring(p.scheme())
        self.assertEqual([v.attrib['BlueprintName'] for v in tree.findall('TestAction/Testables/TestableReference/BuildableReference')],[b.TEST])
    def test_source_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'new';p.create(out)
            app=out/'App';tests=out/'Tests'
            self.assertIn('madcrypto_fixture_main',(app/'fixture.c').read_text())
            self.assertNotIn('FixtureHook.h',(tests/'Entries.h').read_text())
            self.assertIn('testInstalledExistingSelftest',(tests/'PackageTests.swift').read_text())
            self.assertIn('status, 1',(tests/'ObserverTests.swift').read_text())
            with self.assertRaises(FileExistsError): p.create(out)
    def test_exact_products_and_plan(self):
        for rel in b.APPROVED_BUNDLES:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve()
                for path,name,bid,kind in ((b.APP_REL,b.APP,b.APP_ID,'APPL'),(rel,b.TEST,b.TEST_ID,'BNDL')):
                    folder=root/path;folder.mkdir(parents=True)
                    (folder/name).write_bytes(b'synthetic')
                    (folder/'Info.plist').write_bytes(plistlib.dumps(
                        dict(CFBundleExecutable=name,CFBundleIdentifier=bid,CFBundlePackageType=kind)))
                host,test,actual=b.products(root)
                self.assertEqual(actual,rel)
                target=dict(BlueprintName=b.TEST,TestHostPath='__TESTROOT__/'+b.APP_REL,TestBundlePath='__TESTROOT__/'+rel)
                result=b.authored({b.TEST:target},rel)
                target['EnvironmentVariables']={'DYLD_INSERT_LIBRARIES':'/private/dylib'}
                target['TestingEnvironmentVariables']={'DYLD_INSERT_LIBRARIES':'/private/dylib'}
                self.assertEqual(result,b.authored({b.TEST:target},rel))
                self.assertNotIn(b'/private',result)
                target['TestBundlePath']='__TESTROOT__/private.xctest'
                with self.assertRaises(ValueError): b.authored({b.TEST:target},rel)
                (test.parent/'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleExecutable='unapproved')))
                with self.assertRaises(ValueError): b.products(root)
    def test_linkage_boundary_and_platform(self):
        required={'_madcrypto_session_encrypt','_madobs_emit_generic_event'}
        app='\n'.join(required|b.EXPORTS); imports='\n'.join(b.EXPORTS)
        b.verify_linkage(app,'_helper',imports,required)
        for values in [(app,'_madobs_emit_generic_event',imports),
                       (app,'',imports+'\n_madcrypto_session_encrypt'),
                       ('','',imports)]:
            with self.assertRaises(ValueError): b.verify_linkage(*values,required)
        b.verify_platform('    platform 7')
        for platform in ('platform IOS','platform 7\n platform IOS',''):
            with self.assertRaises(ValueError): b.verify_platform(platform)
    def test_workflow_preserves_exact_baseline(self):
        workflow=(p.ROOT/'.github/workflows/ios-obs-hosted.yml').read_text()
        self.assertIn('checkpoint/madcrypto-ios-obs-hosted',workflow)
        self.assertEqual(workflow.count('ios-package-check/simulator.sh'),1)
        self.assertNotIn('upload-artifact',workflow)
        run=(HERE/'run.py').read_text()
        self.assertIn("'-xctestrun',str(plan)",run)
        self.assertNotIn("'-xctestrun',str(receipt)",run)

if __name__=='__main__':unittest.main()
