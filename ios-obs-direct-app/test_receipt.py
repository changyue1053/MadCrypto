import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('direct_receipt',HERE/'receipt.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
NONCE='0123456789abcdef'*2
DEV='01010101-0101-0101-0101-010101010101'
APP='02020202-0202-0202-0202-020202020202'
BUNDLE='org.example.madcrypto.obsqualification'
class Receipt(unittest.TestCase):
    def good(self):
        return dict(version=1, nonce=NONCE,pid=47,outcomes={name:True for name in r.NAMES})
    def test_exact_challenge_pid_and_outcomes(self):
        good=self.good()
        r.verify(json.dumps(good).encode(),NONCE,47)
        for update in [dict(nonce='a'*32),dict(pid=48),dict(pid=True),dict(version=True),dict(extra=7),
                       dict(outcomes={name:1 for name in r.NAMES}),
                       dict(outcomes={name:False for name in r.NAMES}),
                       dict(outcomes={'added':True})]:
            with self.assertRaises(ValueError):r.verify(json.dumps(good|update).encode(),NONCE,47)
        raw=json.dumps(good).encode()
        with self.assertRaises(ValueError):r.verify(b'{"pid":47,'+raw[1:],NONCE,47)
        with self.assertRaises(ValueError):r.verify(raw+b' '*r.MAX,NONCE,47)
    def test_pid_is_exact_bundle_reponse(self):
        self.assertEqual(r.pid(BUNDLE+': 47\n',BUNDLE),47)
        for value in ['other: 47',BUNDLE+': 0',BUNDLE+': 47\n/private/log',BUNDLE+': 2147483648']:
            with self.assertRaises(ValueError):r.pid(value,BUNDLE)
    def test_owned_app_data_and_no_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            data=root/DEV/'data/Containers/Data/Application'/APP;data.mkdir(parents=True)
            app=root/DEV/'data/Containers/Bundle/Application'/APP/'MadCryptoObsHost.app';app.mkdir(parents=True)
            self.assertEqual(r.container(str(data)+'\n',root,DEV,'data'),data)
            self.assertEqual(r.container(str(app),root,DEV,'app'),app)
            for value,kind in [(data,'app'),(app,'data'),(root,'data')]:
                with self.assertRaises(ValueError):r.container(str(value),root,DEV,kind)
            alias=root/'alias';alias.symlink_to(data,target_is_directory=True)
            with self.assertRaises(ValueError):r.container(str(alias),root,DEV,'data')
    def test_receipt_regular_0600_unique(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();item=root/'receipt';item.write_bytes(b'x');item.chmod(0o600)
            self.assertEqual(r.read(item),b'x')
            alias=root/'alias';alias.hardlink_to(item)
            with self.assertRaises(ValueError):r.read(item)
            alias.unlink();alias.symlink_to(item)
            with self.assertRaises(ValueError):r.read(alias)
            item.chmod(0o644)
            with self.assertRaises(ValueError):r.read(item)
    def test_direct_app_only_paths_and_source(self):
        c=(HERE/'main.m').read_text(); runner=(HERE/'run.py').read_text()
        self.assertIn('O_EXCL | O_NOFOLLOW',c);self.assertIn('(void)link(',c)
        for name in r.NAMES:self.assertIn(name,c)
        for call in ('madcrypto_host_abi() == 0x000100','madcrypto_host_selftest() == 0','madcrypto_test_qualification(drain.fileSystemRepresentation) == 1'):
            self.assertIn(call,c)
        self.assertIn('smoke.verify(first,nonce,launched)',runner)
        self.assertIn('audit.fingerprint(installed)!=before',runner)
        for bad in ("'test-without-building'","'build-for-testing'","'spawn'"):
            self.assertNotIn(bad,runner)
if __name__=='__main__':unittest.main()
