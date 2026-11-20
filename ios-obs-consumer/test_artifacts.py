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
    def test_zlib_cleanup_and_fixed_labels(self):
        here=Path(__file__).parent
        self.assertIn('.linkedLibrary("z")',(here/'Consumer/Package.swift').read_text())
        swift=(here/'Consumer/Tests/ConsumerTests/ObserverTests.swift').read_text()
        self.assertNotIn('defer',swift); self.assertNotIn('try?',swift)
        self.assertIn('if status == 1',swift)
        self.assertIn("'ObserverTests/' if name == 'testInstalledPrivateFixtureDrain'",(here/'results.py').read_text())
if __name__=='__main__': unittest.main()
