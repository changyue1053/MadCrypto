"""Publication regressions: no native build needed to test filesystem safety."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("package_host", Path(__file__).resolve().parents[1] / "scripts/package_host.py")
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)

class PublicationTests(unittest.TestCase):
    def test_dangling_output_link_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            link = root / "output"
            target = root / "unintended"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                pack.output_path(link)
            self.assertTrue(link.is_symlink())
            self.assertFalse(target.exists())

    def test_resolve_parent_but_not_final_component(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            real = root / "real"
            real.mkdir()
            link = root / "parent-link"
            link.symlink_to(real, target_is_directory=True)
            self.assertEqual(pack.output_path(link / "new"), real / "new")

    def test_late_collisions_never_replace(self):
        for kind in ("directory", "file", "dangling-link"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                destination = pack.output_path(root / "output")
                source = root / "stage"
                source.mkdir()
                (source / "payload").write_text("staged")
                # Deterministic collision after preflight, before publish.
                if kind == "directory":
                    destination.mkdir()  # Ordinary rename would replace this.
                elif kind == "file":
                    destination.write_text("preserve")
                else:
                    destination.symlink_to(root / "absent")
                with self.assertRaises(FileExistsError):
                    pack.publish_no_replace(source, destination)
                self.assertEqual((source / "payload").read_text(), "staged")
                if kind == "directory":
                    self.assertEqual(list(destination.iterdir()), [])
                elif kind == "file":
                    self.assertEqual(destination.read_text(), "preserve")
                else:
                    self.assertTrue(destination.is_symlink())
                    self.assertFalse((root / "absent").exists())

    def test_new_destination_publishes_complete_directory(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "stage"
            source.mkdir()
            (source / "payload").write_text("complete")
            destination = pack.output_path(root / "output")
            pack.publish_no_replace(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual((destination / "payload").read_text(), "complete")

if __name__ == "__main__":
    unittest.main()
