import subprocess
import tempfile
import unittest
from dependency_check import inspect, generation_class, generate, ARGS
from unittest.mock import patch
import contextlib
import io
from pathlib import Path

GATE = Path(__file__).with_name('dependency_scope.sh')


class Tests(unittest.TestCase):
    def test_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'tree'
            path.write_text('madcrypto-ffi v0.1.0\nmadcrypto-core v0.1.0\nmadcrypto-prims v0.1.0\n[build-dependencies]\ncc v1.4.4\naes-gcm v0.10.3\n')
            self.assertEqual(subprocess.run(['bash', str(GATE), str(path)]).returncode, 0)

    def test_forbidden_and_inspection_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'tree'
            for name in ['openssl-sys', 'aws-lc-sys', 'ring', 'cmake', 'libsqlite3-sys', 'rusqlite', 'madcrypto-store']:
                path.write_text(f'madcrypto-ffi v0.1.0\nmadcrypto-core v0.1.0\nmadcrypto-prims v0.1.0\n{name} v1.0.0\n')
                with self.subTest(name=name):
                    self.assertNotEqual(subprocess.run(['bash', str(GATE), str(path)]).returncode, 0)
            self.assertNotEqual(subprocess.run(['bash', str(GATE), str(path.with_name('missing'))]).returncode, 0)
            self.assertNotEqual(subprocess.run(['bash', str(GATE), temp]).returncode, 0)


class ParseTests(unittest.TestCase):
    def test_preparation_preserves_locked_offline_build_boundary(self):
        script = Path(__file__).with_name('check.sh').read_text()
        self.assertIn('cargo fetch --locked\nstage=android-dependency-generate', script)
        self.assertNotIn('cargo fetch --locked --target', script)
        self.assertIn('cargo rustc --locked --offline', script)
        self.assertIn('--offline', ARGS)
        self.assertIn('--locked', ARGS)
        self.assertIn('normal,build', ARGS)
        self.assertIn('aarch64-linux-android', ARGS)

    def test_invalid_tree(self):
        for text in ['', '\n', 'SECRET_PATH', 'madcrypto-ffi v0.1.0\n', 'other v1.0.0\n']:
            with self.assertRaises(ValueError): inspect(text)

    def test_generation_classes(self):
        for text, label in [('unexpected argument SECRET','arguments'), ('lock file SECRET needs to be updated','locked'), ('attempting HTTP but offline was specified','cache'), ('SECRET credentials','other')]:
            self.assertEqual(generation_class(text), label)

    def test_generation_failure_does_not_reclassify_partial_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'SECRET'
            def fail(args, stdout, stderr, timeout):
                self.assertEqual(args, ARGS)
                stdout.write(b'openssl-sys v0.9.0\n')
                stderr.write(b'error: unexpected argument /SECRET')
                return subprocess.CompletedProcess(args, 101)
            output = io.StringIO()
            with patch('dependency_check.subprocess.run', side_effect=fail), contextlib.redirect_stdout(output):
                self.assertEqual(generate(path), 1)
            self.assertEqual(output.getvalue(), 'FAIL: android-dependency-generate-arguments\n')

    def test_safe_family_output(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'SECRET'
            path.write_text('madcrypto-ffi v0.1.0 (/SECRET)\nmadcrypto-core v0.1.0\nmadcrypto-prims v0.1.0\nopenssl-sys v0.9.0\n')
            result = subprocess.run(['bash',str(GATE),str(path)],capture_output=True,text=True)
            self.assertEqual(result.stdout,'FAIL: android-dependency-forbidden-openssl\n')
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stderr,'')


if __name__ == '__main__': unittest.main()
