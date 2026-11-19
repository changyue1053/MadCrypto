"""Synthetic package/result-format checks only, never mobile execution proof."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout
import io
import subprocess

def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

inspection, results = load('package_inspector'), load('results')

def fixture():
    return ({'totalTestCount': 2, 'passedTests': 2, 'failedTests': 0, 'skippedTests': 0},
            {'testNodes': [{'nodeType': 'Test Case', 'nodeIdentifier': 'PackageTests/'+name+'()',
                            'result': 'Passed'} for name in results.EXPECTED]})

class Formats(unittest.TestCase):
    def test_standard_inspect_not_shadowed(self):
        import inspect
        self.assertTrue(callable(inspect.signature))

    def test_named_pass(self):
        results.verify(*fixture())
    def test_optional_status(self):
        a,b=fixture(); a['testStatus']='Passed'; results.verify(a,b)
        a['testStatus']='Failed'
        with self.assertRaises(results.ResultRejected): results.verify(a,b)
    def test_wrong_counts(self):
        for key in ('totalTestCount','passedTests','failedTests','skippedTests'):
            a,b=fixture(); a[key]=9
            with self.assertRaises(results.ResultRejected): results.verify(a,b)
    def test_summary_only(self):
        a,b=fixture()
        with self.assertRaises(results.ResultRejected): results.verify(a,{})
    def test_case_errors(self):
        for mode in ('duplicate', 'extra', 'missing', 'name', 'skip'):
            a,b=fixture(); cases=b['testNodes']
            if mode=='duplicate': cases[1]=copy.deepcopy(cases[0])
            if mode=='extra': cases.append(copy.deepcopy(cases[0]))
            if mode=='missing': cases.pop()
            if mode=='name': cases[0]['nodeIdentifier']='unexpected'
            if mode=='skip': cases[0]['result']='Skipped'
            with self.assertRaises(results.ResultRejected): results.verify(a,b)
    def test_slices(self):
        entries=[dict(LibraryIdentifier='ios-arm64',LibraryPath='libmadcrypto_ffi.a',HeadersPath='Headers',
                      SupportedPlatform='ios',SupportedArchitectures=['arm64']),
                 dict(LibraryIdentifier='ios-arm64-simulator',LibraryPath='libmadcrypto_ffi.a',HeadersPath='Headers',
                      SupportedPlatform='ios',SupportedArchitectures=['arm64'],SupportedPlatformVariant='simulator')]
        inspection.verify_entries(entries)
        for key,value in [('SupportedArchitectures',['x86_64']),('SupportedPlatform','macos'),
                          ('LibraryIdentifier','../outside'),('HeadersPath','/outside')]:
            wrong=copy.deepcopy(entries);wrong[0][key]=value
            with self.assertRaises(ValueError): inspection.verify_entries(wrong)
        with self.assertRaises(ValueError): inspection.verify_entries(entries[:1])

class InspectorDiagnostics(unittest.TestCase):
    def test_fixed_errors_only(self):
        for error, expected in [
            *[(inspection.Rejected(reason), reason) for reason in inspection.REASONS],
            (inspection.Rejected('arbitrary path text'), 'unexpected-schema'),
            (OSError('arbitrary path text'), 'file-access'),
            (subprocess.CalledProcessError(1, 'arbitrary path text'), 'tool-command'),
            (RuntimeError('arbitrary text'), 'unexpected-schema'),
        ]:
            out, err = io.StringIO(), io.StringIO()
            with patch.object(inspection, 'main', side_effect=error), redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(inspection.run(), 1)
            self.assertEqual(out.getvalue(), '')
            self.assertEqual(err.getvalue(), 'FAIL: package-inspector-' + expected + '\n')
    def test_symbols(self):
        header = b'int madcrypto_selftest(void);'
        inspection.verify_symbols('_madcrypto_selftest\n', header)
        for symbols, reason in [('', 'required-symbols'),
                                ('_madcrypto_selftest\n_madcrypto_debug_trigger_panic\n', 'test-symbols')]:
            with self.assertRaises(inspection.Rejected) as error:
                inspection.verify_symbols(symbols, header)
            self.assertEqual(str(error.exception), reason)
    def test_checks_not_disabled_by_python_optimization(self):
        with self.assertRaises(inspection.Rejected): inspection.require(False, 'header')

class ToolDiagnostics(unittest.TestCase):
    def test_exact_commands(self):
        for tool, args in inspection.TOOLS.items():
            out=io.StringIO()
            response=subprocess.CompletedProcess([],0,'synthetic symbols','private stderr')
            with patch.object(inspection.subprocess,'run',return_value=response) as run, redirect_stdout(out):
                self.assertEqual(inspection.query_tool(tool,'device','synthetic archive'),'synthetic symbols')
            self.assertEqual(run.call_args.args[0],['xcrun',*args,'synthetic archive'])
            self.assertEqual(out.getvalue(),'PASS: package-inspector-'+tool+'-device\n')
    def test_failure_never_accepts_partial_symbols(self):
        for stderr, kind in [('Unknown attribute kind (86) private path', 'bitcode-format'),
                             ('unknown option private path', 'option'),
                             ('file format not recognized private path', 'object-format'),
                             ('private text', 'command')]:
            response=subprocess.CompletedProcess([],1,'_madcrypto_selftest',stderr)
            with patch.object(inspection.subprocess,'run',return_value=response):
                with self.assertRaises(inspection.Rejected) as error:
                    inspection.query_tool('nm','simulator','unused')
            self.assertEqual(str(error.exception),'nm-simulator-'+kind)
    def test_timeout_and_unavailable(self):
        for error, kind in [(OSError('private path'),'unavailable'),
                            (subprocess.TimeoutExpired('private command',90),'timeout')]:
            with patch.object(inspection.subprocess,'run',side_effect=error):
                with self.assertRaises(inspection.Rejected) as caught:
                    inspection.query_tool('lipo','device','unused')
            self.assertEqual(str(caught.exception),'lipo-device-'+kind)

if __name__=='__main__': unittest.main()
