import importlib.util
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('qualified_results',HERE/'results.py')
r=importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
class Orchestration(unittest.TestCase):
    def fixture(self):
        summary=dict(totalTestCount=3,passedTests=3,failedTests=0,skippedTests=0)
        nodes=[]
        for name in r.EXPECTED:
            cls='ObserverTests' if name=='testInstalledPrivateFixtureDrain' else 'PackageTests'
            nodes.append(dict(nodeType='Test Case',nodeIdentifier=cls+'/'+name,result='Passed'))
        return summary,dict(testNodes=nodes)
    def test_exact_three(self): r.verify(*self.fixture())
    def test_fail_closed(self):
        for kind in ('missing','duplicate','skipped','wrong','count'):
            s,t=self.fixture()
            if kind=='missing': t['testNodes'].pop()
            if kind=='duplicate': t['testNodes'][-1]=t['testNodes'][0]
            if kind=='skipped': t['testNodes'][-1]['result']='Skipped'
            if kind=='wrong': t['testNodes'][-1]['nodeIdentifier']='Other/testInstalledPrivateFixtureDrain'
            if kind=='count': s['passedTests']=2
            with self.assertRaises(r.ResultRejected): r.verify(s,t)
    def test_scope(self):
        source=(HERE/'run.py').read_text()
        self.assertIn('if not sys.flags.isolated:',source)
        self.assertIn("'GIT_CONFIG_GLOBAL':os.devnull",source)
        self.assertIn("['rev-parse','HEAD^{tree}'],TREE",source)
        self.assertIn("'-DMADOBS_PACKAGE_BORINGSSL=OFF'",source)
        self.assertIn("'-disableAutomaticPackageResolution'",source)
        self.assertNotIn('simctl\',\'spawn',source)
        self.assertLess(source.index('shutil.rmtree(obs)'),source.index("run(common+['build-for-testing']"))
        self.assertIn('madcrypto_test_qualification($0)',(HERE/'Consumer/Tests/ConsumerTests/ObserverTests.swift').read_text())
if __name__=='__main__': unittest.main()
