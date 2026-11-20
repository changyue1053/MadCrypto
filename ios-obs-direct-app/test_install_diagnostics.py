import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import time

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
    def test_real_child_closes_pipe_before_exit(self):
        def closed(end,deadline=.7):
            src='import os,time;os.close(1);os.close(2);time.sleep(.10);'+end
            return d.invoke([sys.executable,'-I','-c',src],timeout=deadline)
        start=time.monotonic()
        self.assertIsNone(closed('pass'))
        self.assertGreaterEqual(time.monotonic()-start,.09)
        self.assertEqual(closed('raise SystemExit(7)'),'no-domain')
        start=time.monotonic()
        self.assertEqual(closed('pass',deadline=.04),'timeout')
        self.assertGreaterEqual(time.monotonic()-start,.035)
    def test_empty_and_interrupted_selector_wake_continue(self):
        native=d.selectors.DefaultSelector
        class Wake:
            def __init__(self): self.inner=native(); self.count=0
            def __enter__(self): self.inner.__enter__(); return self
            def __exit__(self,*arg): return self.inner.__exit__(*arg)
            def register(self,*arg): return self.inner.register(*arg)
            def select(self,wait):
                self.count+=1
                if self.count==1: return []
                if self.count==2: raise InterruptedError
                return self.inner.select(wait)
        with patch.object(d.selectors,'DefaultSelector',Wake):
            self.assertIsNone(d.invoke([sys.executable,'-I','-c','import time;time.sleep(.08)'],timeout=.7))
if __name__=='__main__':unittest.main()
