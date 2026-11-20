import importlib.util
import io
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('hosted_link_diagnostics',Path(__file__).with_name('link_diagnostics.py'))
d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)

APP='MadCryptoObsHost'
TEST='MadCryptoObsHostTests'
def command(target,project=APP):
    return f"Ld /private/secret/build/private_result normal arm64 (in target '{target}' from project '{project}')\n"
def block(symbols,footer=True):
    head='Undefined symbols for architecture arm64:\n'
    body=''.join('  "'+s+'", referenced from:\n      PRIVATE_STACK in /private/secret/source.o\n' for s in symbols)
    return head+body+('ld: symbol(s) not found for architecture arm64\n' if footer else '')
def scan(data): return d.scan(io.BytesIO(data.encode()))
def log(target,symbols):
    return command(target)+block(symbols)+'The following build commands failed:\n\t'+command(target)

class LinkDiagnostics(unittest.TestCase):
    def test_bridge_and_family(self):
        bridge=sorted(x.decode() for x in d.BRIDGE)
        self.assertEqual(scan(log(TEST,bridge)),'ld-test-bridge-all-other-none-count-two-three')
        self.assertEqual(scan(log(TEST,bridge[:1])),'ld-test-bridge-partial-other-none-count-one')
        self.assertEqual(scan(log(APP,['_madobs_private_path'])),'ld-app-bridge-none-other-sdk-count-one')
        self.assertEqual(scan(log(APP,['_OBJC_CLASS_$_SomePrivate','_malloc'])),'ld-app-bridge-none-other-system-count-two-three')
        self.assertEqual(scan(log(APP,['_private_symbol','_madcrypto_private','_malloc','_private_other'])),
                         'ld-app-bridge-none-other-mixed-count-four-plus')
    def test_target_requires_failed_summary(self):
        self.assertEqual(scan(command(TEST)+block(['_secret'])),'ld-unknown-block-no-summary')
        self.assertEqual(scan(command(TEST)+block(['_secret'])+'The following build commands failed:\n'+command(APP)),
                         'ld-app-block-unparsed')
        self.assertEqual(scan(log(TEST,['_secret'])+command(APP)),'ld-unknown-block-ambiguous')
        self.assertEqual(scan(log('PrivateTarget',['_secret'])),'ld-unknown-block-unparsed')
    def test_exact_context_arch_and_failure_set(self):
        symbols=['_madcrypto_host_abi']
        summary='The following build commands failed:\n'
        self.assertEqual(scan(block(symbols)+summary+command(TEST)),'ld-test-block-unparsed')
        self.assertEqual(scan(command('PrivateTarget')+block(symbols)+summary+command(TEST)),
                         'ld-test-block-unparsed')
        self.assertEqual(scan(log(TEST,symbols)+'CompileC /private/source.o\n(2 failures)\n'),
                         'ld-unknown-block-ambiguous')
        wrong=block(symbols).replace('not found for architecture arm64','not found for architecture x86_64')
        self.assertEqual(scan(command(TEST)+wrong+summary+command(TEST)), 'ld-unknown-block-unparsed')
        self.assertEqual(scan(log(TEST,symbols)+'(2 failures)\n'),'ld-unknown-block-ambiguous')
        self.assertEqual(scan(command(TEST)+'CompileC /private/source.o\n'+block(symbols)+summary+command(TEST)),
                         'ld-test-block-unparsed')
        self.assertEqual(scan(log(TEST,symbols)+'(1 failure)\n'),'ld-test-bridge-partial-other-none-count-one')
    def test_interleaved_command_invalidates_open_block(self):
        summary='The following build commands failed:\n'
        for intervening in (command(APP),command(TEST),'CompileC /private/file.o\n','SwiftCompile /private/file.swift\n'):
            body=block(['_madcrypto_host_abi']).replace('ld: symbol(s)',intervening+'ld: symbol(s)')
            self.assertEqual(scan(command(TEST)+body+summary+command(TEST)),
                             'ld-unknown-block-ambiguous')
    def test_stays_bounded_and_does_not_echo_input(self):
        raw=log(APP,['_Sensitive_Name123','_madcrypto_secret_fragment'])
        result=scan(raw)
        for token in ['Sensitive','Name123','secret','private_result','source.o','fragment','STACK']:
            self.assertNotIn(token,result)
        self.assertEqual(scan('A'*(d.MAX_LINE+2)),'ld-unknown-block-truncated')
        self.assertEqual(scan('x\n'*(d.MAX_RECORDS+1)),'ld-unknown-block-truncated')
        self.assertEqual(d.scan(io.BytesIO(b'a'*(d.MAX_BYTES+1))),'ld-unknown-block-truncated')
    def test_no_unproven_symbol_family(self):
        broken=command(TEST)+block(['_secret'],footer=False)+'The following build commands failed:\n'+command(TEST)
        self.assertEqual(scan(broken),'ld-test-block-incomplete')
        malformed=log(TEST,['_private symbol'])
        self.assertEqual(scan(malformed),'ld-unknown-block-unparsed')
        self.assertEqual(scan(command(TEST)+block(['_a'])+block(['_b'])+'The following build commands failed:\n'+command(TEST)),
                         'ld-test-block-ambiguous')

if __name__=='__main__': unittest.main()
