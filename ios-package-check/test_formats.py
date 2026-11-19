"""Synthetic package/result-format checks only, never mobile execution proof."""
import copy
import importlib.util
from pathlib import Path
import unittest

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

if __name__=='__main__': unittest.main()
