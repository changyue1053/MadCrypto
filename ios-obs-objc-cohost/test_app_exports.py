import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
a=load('actual_exports',HERE/'app_exports.py')
h=load('hosted',HERE.parent/'ios-obs-hosted/project.py')
p=load('cohost',HERE/'project.py')
class ExportEvidence(unittest.TestCase):
    def test_requires_native_trie_and_bounds(self):
        def fixture(commands,cpu=0x0100000c,kind=2):
            return struct.pack('<8I',0xfeedfacf,cpu,0,kind,len(commands),sum(map(len,commands)),0,0)+b''.join(commands)+b'\0'*4
        modern=struct.pack('<4I',0x80000033,16,48,4)
        legacy=struct.pack('<12I',0x80000022,48,*([0]*8),80,4)
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/'app'
            for commands,wanted in [([modern],(48,4)),([legacy],(80,4))]:
                binary.write_bytes(fixture(commands))
                self.assertEqual(a.trie_range(binary),wanted)
            for data in [fixture([modern,legacy]),fixture([modern],cpu=7),fixture([modern],kind=6),
                         fixture([modern])[:-1],fixture([struct.pack('<4I',0x2,16,0,4)]),
                         fixture([struct.pack('<4I',0x80000033,16,48,0)])]:
                binary.write_bytes(data)
                with self.assertRaises(ValueError): a.trie_range(binary)
    def test_classifies_only_exact_local_exports(self):
        header='/private/fixture:\n -exports:\n offset symbol\n'
        one='  0x00000128 '+a.DRIVER+'\n'; two='  0x00000150 '+a.META+'\n'
        other='  0x00000090 _private_symbol\n'
        self.assertEqual(a.classify(header+one+two),'class-and-metaclass')
        self.assertEqual(a.classify(header+two),'metaclass-only')
        self.assertEqual(a.classify(header+one),'class-only')
        self.assertEqual(a.classify(header+other),'neither')
        for invalid in (header+one+one,header+one.strip()+' [weak-def]\n',
                        header+' [re-export] '+a.DRIVER+' (from libExample)\n',
                        header+'no exported symbol information\n','nm '+one):
            with self.assertRaises(ValueError):a.classify(invalid)
    def test_sdk_symbols_cannot_join_the_export_surface(self):
        header='/private/fixture:\n -exports:\n offset symbol\n'
        table=header+'0x00000128 '+a.DRIVER+'\n0x00000150 '+a.META+'\n'
        self.assertEqual(a.classify(table,reject_sdk_exports=True),'class-and-metaclass')
        for invalid in ('0x00000090 _madcrypto_host_abi\n','0x00000090 _madobs_start\n',
                        '[re-export] _imobs_other (from example)\n'):
            with self.assertRaises(ValueError):a.classify(table+invalid,reject_sdk_exports=True)
    def test_isolation_keeps_exact_authored_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp)/'project'; graph=p.create(h,stage)
            objects=graph['objects']; r=h.ident
            before=[objects[r(k)].copy() for k in (30,40,41,70,71)]
            a.isolate(h,graph,stage)
            self.assertEqual([objects[r(k)] for k in (30,40,41,70,71)],before)
            self.assertEqual(objects[r(1)]['targets'],[r(30)])
            self.assertNotIn(r(31),objects)
            folder=stage/(h.APP+'.xcodeproj')/'xcshareddata/xcschemes'
            self.assertEqual([x.name for x in folder.iterdir()],['AppExportsOnly.xcscheme'])
            self.assertIsNone(ET.parse(folder/'AppExportsOnly.xcscheme').find('TestAction'))
    def test_build_only_evidence_route_does_not_boot(self):
        text=(HERE/'run.py').read_text()
        before=text.split('        if export_only:',1)[1].split("        try:\n            run(['xcrun','simctl','boot'",1)[0]
        self.assertIn('inspect_driver_exports(only,binary)',before)
        self.assertIn("['xcrun','dyld_info','-exports',str(binary)]",text)
        self.assertIn('only.trie_range(binary)',text)
        self.assertIn("'/usr/bin/codesign','--verify','--strict'",before)
        self.assertNotIn("simctl','boot",before)
        self.assertNotIn('test-without-building',before)
        self.assertNotIn('nm',before)
if __name__=='__main__': unittest.main()
