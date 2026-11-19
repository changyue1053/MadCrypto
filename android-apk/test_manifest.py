import hashlib,tempfile,unittest
from pathlib import Path
from verify import verify_package
class Tests(unittest.TestCase):
    def test_identity_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);files={}
            for name in ('include/madcrypto.h','lib/libmadcrypto_ffi.a','notices/LICENSE','notices/THIRD_PARTY.md'):
                p=root/name;p.parent.mkdir(exist_ok=True);p.write_bytes(name.encode());files[name]=hashlib.sha256(p.read_bytes()).hexdigest()
            m={'source_commit':'a'*40,'target':'aarch64-linux-android','api':23,'ndk':'28.2.13676358','rust':'1.100.0','android_execution':False,'redistribution':False,'files':files}
            verify_package(root,m,'a'*40)
            with self.assertRaises(ValueError):verify_package(root,m,'b'*40)
            (root/'lib/libmadcrypto_ffi.a').write_bytes(b'changed')
            with self.assertRaises(ValueError):verify_package(root,m,'a'*40)
    def test_original_gate_unchanged_path(self):
        root=Path(__file__).resolve().parents[1]
        text=(root/'android-apk/verify.py').read_text()
        self.assertIn('static-to-shared-no-fallback',text)
        self.assertNotIn('cargo rustc',text)
        self.assertIn("'--dynamic','--defined-only'",text)
        self.assertIn("'TEXTREL' in tags",text)
if __name__=='__main__':unittest.main()
