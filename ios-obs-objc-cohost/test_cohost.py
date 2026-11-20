import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
host=load('hosted',HERE.parent/'ios-obs-hosted/project.py')
b=load('binding',HERE.parent/'ios-obs-hosted/binding.py')
p=load('cohost_project',HERE/'project.py')
proof=load('proof',HERE/'proof.py')

class Cohost(unittest.TestCase):
    def test_owns_archives_in_app_and_locks_three_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst=Path(tmp)/'consumer';objects=p.create(host,dst)['objects'];r=host.ident
            self.assertEqual(objects[r(70)]['buildSettings']['ENABLE_DEBUG_DYLIB'],'NO')
            self.assertEqual(objects[r(71)]['buildSettings']['OTHER_LDFLAGS'],
                             host.document()['objects'][r(71)]['buildSettings']['OTHER_LDFLAGS'])
            self.assertEqual(objects[r(43)]['files'],[])
            self.assertEqual(objects[r(71)]['buildSettings']['EXPORTED_SYMBOLS_FILE'],'$(PROJECT_DIR)/App/DriverExports.txt')
            self.assertNotIn('EXPORTED_SYMBOLS_FILE',objects[r(72)]['buildSettings'])
            self.assertEqual((dst/'App/DriverExports.txt').read_text().splitlines(),
                             ['_OBJC_CLASS_$_MadCryptoCohostDriver','_OBJC_METACLASS_$_MadCryptoCohostDriver'])
            self.assertEqual(objects[r(72)]['buildSettings']['BUNDLE_LOADER'],'$(TEST_HOST)')
            self.assertNotIn('OTHER_LDFLAGS',objects[r(72)]['buildSettings'])
            self.assertNotIn('SWIFT_OBJC_BRIDGING_HEADER',objects[r(72)]['buildSettings'])
            names=['testInstalledABIVersion','testInstalledExistingSelftest','testInstalledPrivateFixtureDrain']
            test=(dst/'Tests/CohostTests.mm').read_text()
            for name in names:self.assertIn('- (void)'+name,test)
            self.assertNotIn('madcrypto_',test)
            self.assertIn('madcrypto_fixture_main',(dst/'App/fixture.c').read_text())
            driver=(dst/'App/Driver.mm').read_text()
            self.assertIn('__attribute__((visibility("default")))',driver)
            for phrase in ('madcrypto_host_abi() == 0x000100','madcrypto_host_selftest() == 0',
                           'madcrypto_test_qualification(folder.fileSystemRepresentation) == 1'):
                self.assertIn(phrase,driver)
    def test_linkage_rejects_sdk_in_xctest(self):
        own='\n'.join([proof.DRIVER,'_madcrypto_fixture_main','_madobs_stop'])
        proof.symbols(own,proof.DRIVER,proof.DRIVER,{'_madcrypto_fixture_main','_madobs_stop'})
        for app,test,undef in ((own,proof.DRIVER+'\n_madobs_stop',proof.DRIVER),
                              (own,proof.DRIVER,'_madcrypto_host_abi'),
                              ('_madobs_stop',proof.DRIVER,proof.DRIVER)):
            with self.assertRaises(ValueError):proof.symbols(app,test,undef,{'_madobs_stop'})
    def test_receipt_refuses_foreign_product_and_loader(self):
        path=b.APPROVED_BUNDLES[1]
        root='__TESTROOT__/'
        target=dict(BlueprintName=b.TEST,TestHostPath=root+b.APP_REL,TestBundlePath='__TESTHOST__/PlugIns/'+b.TEST+'.xctest',
                    DependentProductPaths=[root+b.APP_REL,root+path],TestHostBundleIdentifier=b.APP_ID,
                    TestingEnvironmentVariables={'DYLD_LIBRARY_PATH':root+b.CONFIG})
        proof.receipt({b.TEST:target},b,[path])
        for change in [dict(TestBundlePath=root+'other.xctest'),dict(TestHostPath='/other.app'),
                       dict(DependentProductPaths=['/tmp/external']),
                       dict(EnvironmentVariables={'PATH':'/private'}),
                       dict(TestingEnvironmentVariables={'DYLD_INSERT_LIBRARIES':'/other.dylib'}),
                       dict(SkipTestIdentifiers=['test']),dict(TestExecutionOrdering='random')]:
            with self.assertRaises(ValueError):proof.receipt({b.TEST:target|change},b,[path])
        config={'Name':'Debug','TestTargets':[target]}
        metadata={'FormatVersion':2}
        proof.receipt({'__xctestrun_metadata__':metadata,'TestConfigurations':[config]},b,[path])
        for override in ({'EnvironmentVariables':{'PATH':'/private'}},{'OnlyTestIdentifiers':['test']}):
            with self.assertRaises(ValueError):
                proof.receipt({'__xctestrun_metadata__':metadata,'TestConfigurations':[config|override]},b,[path])
            with self.assertRaises(ValueError):
                proof.receipt({'__xctestrun_metadata__':metadata,'TestConfigurations':[config]}|override,b,[path])
    def test_receipt_reports_fixed_reasons_without_exposing_values(self):
        root='__TESTROOT__/'
        side=b.APPROVED_BUNDLES[0]
        target=dict(BlueprintName=b.TEST,TestHostPath=root+b.APP_REL,
                    TestBundlePath=root+side,DependentProductPaths=[root+b.APP_REL,root+side])
        def rejected(doc,expected):
            with self.assertRaises(proof.ReceiptRejected) as result:
                proof.receipt(doc,b,[side])
            self.assertEqual(str(result.exception),'receipt-policy')
            self.assertEqual(result.exception.reasons,expected)
        for change,reason in (({'BlueprintName':'PRIVATE-NAME'},'target-id'),
                              ({'UseDestinationArtifacts':True},'target-mode'),
                              ({'CommandLineArguments':['PRIVATE-ARG']},'target-arguments'),
                              ({'TestBundleDestinationRelativePath':'PRIVATE-PATH'},'target-alternate-path'),
                              ({'EnvironmentVariables':{'WHAT':'PRIVATE-VALUE'}},'scheme-environment'),
                              ({'TestingEnvironmentVariables':False},'loader-shape'),
                              ({'TestingEnvironmentVariables':{'DYLD_LIBRARY_PATH':['PRIVATE']}},'loader-value-type')):
            rejected({b.TEST:target|change},(reason,))
        loader={'PRIVATE-KEY':'PRIVATE-VALUE','DYLD_FRAMEWORK_PATH':
                '__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/Frameworks:'+root+b.CONFIG,
                'DYLD_LIBRARY_PATH':root+b.CONFIG+':__PLATFORMS__/iPhoneSimulator.platform/Developer/Library',
                'XCInjectBundleInto':'/private/PATH'}
        failures=dict(TestHostPath='/PRIVATE/HOST',TestBundlePath=['PRIVATE-BUNDLE'],
                      DependentProductPaths=[{'PRIVATE':'VALUE'}],TestingEnvironmentVariables=loader)
        expected=('receipt-host','receipt-test','receipt-dependencies','loader-other-key',
                  'loader-framework-path-reversed-stock','loader-library-path-developer-library-after',
                  'loader-inject-host')
        for doc in ({b.TEST:target|failures},
                    {'__xctestrun_metadata__':{'FormatVersion':2,'ExtraNativeMeta':'PRIVATE'},
                     'TestConfigurations':[{'Name':'Debug','TestTargets':[target|failures]}]}):
            rejected(doc,expected)
        rejected({'__xctestrun_metadata__':{'FormatVersion':True}},('receipt-format',))
    def test_same_build_and_execution_flags_no_direct_install(self):
        src=(HERE/'run.py').read_text()
        self.assertIn("'ENABLE_DEBUG_DYLIB=NO'",src)
        self.assertIn("run(project+args+['build-for-testing']",src)
        self.assertIn("run(['xcodebuild','-xctestrun',str(selected),'-destination','platform=iOS Simulator,id='+uuid",src)
        self.assertNotIn("run(project+args+['-resultBundlePath'",src)
        self.assertIn('if identity()!=(selected,before)',src)
        self.assertIn('outcome=inspect_driver_exports(only,host)',src)
        self.assertLess(src.index('outcome=inspect_driver_exports(only,host)'),src.index("run(['xcodebuild','-xctestrun'"))
        self.assertIn("HERE/'results.py'",src)
        self.assertIn("except Exception: raise Failed('objc-cohost-receipt-read')",src)
        self.assertIn("if not receipt_only:\n                run(['xcrun','simctl','boot'",src)
        evidence=src.index("if receipt_only:\n                print('PASS: objc-cohost-receipt-evidence-build-only'")
        self.assertLess(evidence,src.index("run(['xcodebuild','-xctestrun'"))
        self.assertIn("for action in (['delete'] if receipt_only else ['shutdown','delete']):",src)
        self.assertNotIn("'get_app_container'",src)
        self.assertNotIn("'simctl','install'",src)
if __name__=='__main__': unittest.main()
