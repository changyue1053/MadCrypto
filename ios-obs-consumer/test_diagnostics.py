import importlib.util
from pathlib import Path
import io
import unittest
spec=importlib.util.spec_from_file_location('qualified_diagnostics',Path(__file__).with_name('diagnostics.py'))
d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
class Diagnostics(unittest.TestCase):
    def test_categories(self):
        cases={'header-missing':b"fatal error: 'synthetic.h' file not found",'module-definition':b'error: redefinition of module',
        'module-import':b"error: no such module 'Synthetic'",'undefined-symbol':b'Undefined symbols for architecture arm64:',
        'duplicate-symbol':b'duplicate symbol _synthetic', 'library-missing':b'ld: library not found for -lSynthetic',
        'platform-mismatch':b'building for iOS Simulator but linking in object file built for iOS',
        'signing':b'error: missing provisioning profile','package-resolution':b'Could not resolve package dependencies',
        'swift-compile':b'Fixture.swift:1:2: error: synthetic','c-compile':b'fixture.c:1:2: error: synthetic'}
        for expected,data in cases.items():
            with self.subTest(expected=expected): self.assertEqual(d.classify(data),expected)
    def test_never_echo_input(self):
        for data in [b'private/path/secret-token',b'',b'error: unknown',b'x'*(d.LIMIT+1),None]:
            self.assertEqual(d.classify(data),'other')
    def test_bounded_head_tail(self):
        data=b'a'*(d.LIMIT+100)+b'Undefined symbols for architecture arm64:'
        result=d.bounded_read(io.BytesIO(data))
        self.assertEqual(len(result),d.LIMIT)
        self.assertEqual(d.classify(result),'undefined-symbol')
    def test_only_failed_consumer_phase(self):
        source=Path(__file__).with_name('run.py').read_text()
        self.assertIn("if stage=='consumer-link':",source)
        self.assertIn('except subprocess.CalledProcessError:',source)
        self.assertNotIn('print(data',source)
    def test_middle_and_command_phase(self):
        log=(b'x'*100+b'\n')*6000+b"error: binary target 'PRIVATE' could not be mapped to an artifact\n"+(b'x'*100+b'\n')*6000+b'CompileC PRIVATE/PATH\n'
        self.assertEqual(d.scan(io.BytesIO(log)),('binary-artifact','compile-c','complete'))
    def test_early_categories(self):
        for code,text in [('package-product','product missing'),('package-target','target missing'),
                          ('build-lock','build database locked'),('destination','destination missing'),
                          ('preparation','PIF transfer failed'),('xcode-error','unknown')]:
            self.assertEqual(d.scan(io.BytesIO(('error: '+text+'\n').encode())),(code,'none','complete'))
    def test_truncated_and_long_line_no_injection(self):
        result=d.scan(io.BytesIO(b'x'*(d.SCAN_BYTES+1)))
        self.assertEqual(result,('other','none','truncated'))
        log=b'x'*d.LINE_BYTES+b'error: binary target SECRET\nLd PRIVATE\n'
        self.assertEqual(d.scan(io.BytesIO(log)),('other','link','truncated'))
        self.assertEqual(d.scan(io.BytesIO(b'\n'*(d.SCAN_RECORDS+1))),('other','none','truncated'))
    def test_phase_allowlist(self):
        for token,expected in [('Resolve Package Graph','package'),('ScanDependencies PRIVATE','scan'),
                               ('SwiftCompile PRIVATE','compile-swift'),('Ld PRIVATE','link'),('CodeSign PRIVATE','sign')]:
            self.assertEqual(d.scan(io.BytesIO((token+'\n').encode())),('other',expected,'complete'))
if __name__=='__main__': unittest.main()
