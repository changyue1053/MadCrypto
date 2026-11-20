import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('qualified_artifacts',Path(__file__).with_name('artifacts.py'))
a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
class Artifacts(unittest.TestCase):
    def target(self):
        return dict(BlueprintName=a.NAME,TestBundlePath='__TESTROOT__/'+a.BUNDLE,TestHostPath='__PLATFORMS__/'+a.HOST)
    def test_target_overrides(self):
        changes=[('UseDestinationArtifacts',True),('IsUITestBundle',True),('IsAppHostedTestBundle',True),
                 ('OnlyTestIdentifiers',['x']),('SkipTestIdentifiers',['x']),('CommandLineArguments',['x']),
                 ('EnvironmentVariables',{'DYLD_INSERT_LIBRARIES':'/outside'}),
                 ('TestingEnvironmentVariables',{'DYLD_INSERT_LIBRARIES':'/outside'}),
                 ('TestingEnvironmentVariables',{'DYLD_LIBRARY_PATH':'/outside'}),
                 ('DependentProductPaths',['/outside']),('TestHostPath','/outside'),
                 ('UnknownExecutionFlag',True)]
        for key,value in changes:
            t=self.target(); t[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): a.target({a.NAME:t})
        good={'__xctestrun_metadata__':{'FormatVersion':2},'TestConfigurations':[{'TestTargets':[self.target()]}]}
        a.target(good)
        good['TestConfigurations'][0]['TestTargets'].append(self.target())
        with self.assertRaises(ValueError): a.target(good)
    def test_documented_plan_is_inert_and_strict(self):
        doc={'__xctestrun_metadata__':{'FormatVersion':2},
             'TestConfigurations':[{'Name':'Configuration 1','TestTargets':[self.target()]}]}
        expected=a.target(doc)
        for is_default in (True,False):
            doc['TestPlan']={'Name':'MadCryptoPackageCheck (Preview)','IsDefault':is_default}
            self.assertEqual(a.target(doc),expected)
        for bad in [None,{}, {'Name':'Plan'}, {'Name':'Plan','IsDefault':1},
                    {'Name':'/private/path','IsDefault':True},
                    {'Name':'Plan\nInjected','IsDefault':True},
                    {'Name':'A'*129,'IsDefault':True},
                    {'Name':'Plan','IsDefault':True,'TestTargets':[]}]:
            with self.subTest(bad=bad),self.assertRaises(a.Rejected) as ctx:
                a.target(dict(doc,TestPlan=bad))
            self.assertEqual(ctx.exception.code,'test-plan-metadata')
        for bad,code in [(dict(doc,Unknown={}), 'manifest-top-fields'),
                         (dict(doc,__xctestrun_metadata__={'FormatVersion':2,'Unknown':True}), 'manifest-metadata'),
                         (dict(doc,TestConfigurations=[{'Name':123,'TestTargets':[self.target()]}]), 'configuration-name'),
                         (dict(doc,TestConfigurations=[{'Name':'Default','IsEnabled':False,'TestTargets':[self.target()]}]), 'configuration-disabled')]:
            with self.assertRaises(a.Rejected) as ctx: a.target(bad)
            self.assertEqual(ctx.exception.code,code)
        with self.assertRaises(a.Rejected):
            a.target({a.NAME:self.target(),'TestPlan':doc['TestPlan']})
    def fixture(self,root):
        bundle=root/'Debug-iphonesimulator'/(a.NAME+'.xctest'); bundle.mkdir(parents=True)
        (bundle/a.NAME).write_bytes(b'synthetic-not-mach-o')
        (bundle/'_CodeSignature').mkdir(); (bundle/'_CodeSignature/CodeResources').write_bytes(b'signature')
        manifest=root/'synthetic.xctestrun'
        manifest.write_bytes(plistlib.dumps({'__xctestrun_metadata__':{'FormatVersion':2},'TestConfigurations':[{'TestTargets':[self.target()]}]}))
        host=root/'platforms'/a.HOST; host.parent.mkdir(parents=True); host.write_bytes(b'synthetic-host')
        return manifest.resolve(),(bundle/a.NAME).resolve()
    def test_binding_and_signature_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); expected=self.fixture(root)
            self.assertEqual(a.identify(root,root/'platforms'),expected)
            before=a.fingerprint(root)
            expected[1].with_name('_CodeSignature').joinpath('CodeResources').write_bytes(b'changed')
            self.assertNotEqual(before,a.fingerprint(root))
    def test_manifest_and_escape_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); manifest,binary=self.fixture(root)
            (root/'duplicate.xctestrun').write_bytes(manifest.read_bytes())
            with self.assertRaises(ValueError): a.identify(root,root/'platforms')
            (root/'duplicate.xctestrun').unlink()
            manifest.write_bytes(plistlib.dumps({'TestBundlePath':'/outside/test.xctest'}))
            with self.assertRaises(ValueError): a.identify(root,root/'platforms')
            (root/'escape').symlink_to('/tmp')
            with self.assertRaises(ValueError): a.fingerprint(root)
    def test_defined_symbol_set(self):
        a.verify_symbols('\n'.join(a.REQUIRED))
        for missing in a.REQUIRED:
            with self.assertRaises(ValueError): a.verify_symbols('\n'.join(a.REQUIRED-{missing}))
    def test_diagnostics_fixed_and_precise(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaises(a.Rejected) as ctx:
                a.identify(root,root/'platforms')
            self.assertEqual(ctx.exception.code,'manifest-missing')
            manifest,binary=self.fixture(root)
            manifest.write_bytes(b'invalid/PRIVATE/plist')
            with self.assertRaises(a.Rejected) as ctx:
                a.identify(root,root/'platforms')
            self.assertEqual(str(ctx.exception),'manifest-parse')
            manifest.write_bytes(b'x'*(1024*1024+1))
            with self.assertRaises(a.Rejected) as ctx:
                a.identify(root,root/'platforms')
            self.assertEqual(ctx.exception.code,'manifest-size')
        self.assertEqual(str(a.Rejected('private/path')),'unexpected')
        for missing,code in [('_madcrypto_session_encrypt','symbols-crypto'),
                             ('_madcrypto_fixture_main','symbols-bridge'),
                             ('_madobs_stop','symbols-obs')]:
            with self.assertRaises(a.Rejected) as ctx:
                a.verify_symbols('\n'.join(a.REQUIRED-{missing}))
            self.assertEqual(ctx.exception.code,code)
    def test_authored_plan_never_executes_unknown_source_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            receipt,binary=self.fixture(root)
            document=plistlib.loads(receipt.read_bytes())
            document['UnreviewedTopLevel']={'EnvironmentVariables':{'DYLD_INSERT_LIBRARIES':'/private/inject'}}
            receipt.write_bytes(plistlib.dumps(document))
            original=receipt.read_bytes()
            with self.assertRaises(a.Rejected) as ctx: a.identify(root,root/'platforms')
            self.assertEqual(ctx.exception.code,'manifest-top-fields')
            found,exe,plan=a.bind_execution(root,root/'platforms')
            self.assertEqual((found,exe),(receipt,binary))
            self.assertEqual(plan,root/a.AUTHORED)
            self.assertNotEqual(plan,receipt)
            self.assertEqual(receipt.read_bytes(),original)
            reviewed=plistlib.loads(plan.read_bytes())
            self.assertEqual(a.target(reviewed),self.target())
            self.assertNotIn(b'private',plan.read_bytes())
            self.assertNotIn(b'UnreviewedTopLevel',plan.read_bytes())
            self.assertEqual(a.bind_execution(root,root/'platforms',existing_plan=True),(found,exe,plan))
            before=a.snapshot(root,root/'platforms')
            receipt.write_bytes(original+b'\n')
            self.assertNotEqual(a.snapshot(root,root/'platforms'),before)
            receipt.write_bytes(original)
            plan.write_bytes(plan.read_bytes()+b'\n')
            with self.assertRaises(a.Rejected) as ctx:
                a.bind_execution(root,root/'platforms',existing_plan=True)
            self.assertEqual(ctx.exception.code,'authored-bytes')
    def test_unsafe_source_target_not_projected_out(self):
        for field,value in [('EnvironmentVariables',{'DYLD_INSERT_LIBRARIES':'/private/inject'}),
                            ('TestHostPath','/private/host'),('OnlyTestIdentifiers',['case']),
                            ('DependentProductPaths',['/private/product']),('UnknownTargetField',True)]:
            t=self.target();t[field]=value
            with self.subTest(field=field),self.assertRaises(a.Rejected):
                a.authored_plan({'__xctestrun_metadata__':{'FormatVersion':2},
                                 'TestConfigurations':[{'TestTargets':[t]}],
                                 'UnknownTopLevel':True})
    def test_zlib_cleanup_and_fixed_labels(self):
        here=Path(__file__).parent
        self.assertIn('.linkedLibrary("z")',(here/'Consumer/Package.swift').read_text())
        swift=(here/'Consumer/Tests/ConsumerTests/ObserverTests.swift').read_text()
        self.assertNotIn('defer',swift); self.assertNotIn('try?',swift)
        self.assertIn('if status == 1',swift)
        self.assertIn("'ObserverTests/' if name == 'testInstalledPrivateFixtureDrain'",(here/'results.py').read_text())
if __name__=='__main__': unittest.main()
