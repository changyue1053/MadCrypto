import importlib.util
from pathlib import Path
import sys
import unittest

spec=importlib.util.spec_from_file_location('install_diagnostics',Path(__file__).with_name('install_diagnostics.py'))
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
class Installer(unittest.TestCase):
    def test_realistic_nested_shape_without_paths(self):
        raw=b"""An error was encountered processing the command (domain=IXUserPresentableErrorDomain, code=1):
Could not inspect /Users/private/Payload/App.app
Underlying error (domain=MIInstallerErrorDomain, code=35):
    Unable to load /private/fixture/Info.plist
"""
        self.assertEqual(d.classify(raw),'outer-ixui-1-inner-mi-35')
        for term in ('Users','Payload','Info.plist','fixture'):
            self.assertNotIn(term,d.classify(raw))
    def test_unknown_ambiguous_and_bounds(self):
        main=b'An error was encountered processing the command (domain=PrivateCompanyDomain, code=471112):\n'
        nested=b'Underlying error (domain=com.apple.CoreSimulator.SimError, code=471113):\n'
        self.assertEqual(d.classify(main+nested),'outer-other-domain-inner-sim-other-code')
        self.assertEqual(d.classify(main+main),'ambiguous-domain')
        self.assertEqual(d.classify(b'private command line'),'no-domain')
        self.assertEqual(d.classify(b'x'*(d.LIMIT+1)),'output-limit')
    def test_process_statuses(self):
        def py(source,**kw): return d.invoke([sys.executable,'-I','-c',source],**kw)
        self.assertIsNone(py('pass'))
        self.assertEqual(py('raise SystemExit(42)'),'no-domain')
        self.assertEqual(py('import os,signal;os.kill(os.getpid(),signal.SIGTERM)'),'signal')
        self.assertEqual(py('import os;os.write(1,b"x"*20000)',limit=1024),'output-limit')
        self.assertEqual(py('import time;time.sleep(1)',timeout=0.05),'timeout')
        self.assertEqual(d.invoke(['/nonexistent/fixture/binary']),'start')
if __name__=='__main__':unittest.main()
