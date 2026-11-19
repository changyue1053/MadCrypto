import subprocess
import tempfile
import unittest
from pathlib import Path

GATE = Path(__file__).with_name('dependency_scope.sh')


class Tests(unittest.TestCase):
    def test_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'tree'
            path.write_text('madcrypto-ffi v0.1.0\ncc v1.4.4\naes-gcm v0.10.3\n')
            self.assertEqual(subprocess.run(['bash', str(GATE), str(path)]).returncode, 0)

    def test_forbidden_and_inspection_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'tree'
            for name in ['openssl-sys', 'aws-lc-sys', 'ring', 'cmake', 'libsqlite3-sys', 'rusqlite', 'madcrypto-store']:
                path.write_text(f'madcrypto-ffi v0.1.0\n{name} v1.0.0\n')
                with self.subTest(name=name):
                    self.assertNotEqual(subprocess.run(['bash', str(GATE), str(path)]).returncode, 0)
            self.assertNotEqual(subprocess.run(['bash', str(GATE), str(path.with_name('missing'))]).returncode, 0)
            self.assertNotEqual(subprocess.run(['bash', str(GATE), temp]).returncode, 0)


if __name__ == '__main__': unittest.main()
