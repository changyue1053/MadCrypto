import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('pre',Path(__file__).with_name('preexecution.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Preexecution(unittest.TestCase):
    def test_destination(self):
        uuid='12345678-1234-1234-1234-123456789012'
        line='{ platform:iOS Simulator, arch:arm64, id:'+uuid+', OS:26.2, name:Synthetic }'
        p.destination(line,uuid)
        for bad in [line+line,line.replace('arm64','x86_64'),'Ineligible destinations\n'+line,line.replace(uuid,'other')]:
            with self.assertRaises(ValueError): p.destination(bad,uuid)
    def test_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); folder=root/'ios-arm64-simulator';folder.mkdir()
            (folder/'libtest.a').write_bytes(b'synthetic');(folder/'Headers').mkdir()
            item=dict(SupportedPlatform='ios',SupportedPlatformVariant='simulator',SupportedArchitectures=['arm64'],LibraryIdentifier=folder.name,LibraryPath='libtest.a',HeadersPath='Headers')
            def save(items): (root/'Info.plist').write_bytes(plistlib.dumps(dict(AvailableLibraries=items)))
            save([item]);self.assertEqual(p.simulator_slice(root),(folder/'libtest.a').resolve())
            for changed in [dict(item,SupportedPlatformVariant='device'),dict(item,SupportedArchitectures=['x86_64']),dict(item,LibraryPath='../escape')]:
                save([changed])
                with self.assertRaises(ValueError):p.simulator_slice(root)
            save([item,item])
            with self.assertRaises(ValueError):p.simulator_slice(root)
if __name__=='__main__':unittest.main()
