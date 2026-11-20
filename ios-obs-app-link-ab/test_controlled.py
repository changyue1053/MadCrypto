import importlib.util
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
c=load('controlled',HERE/'controlled.py')
p=load('project',HERE.parent/'ios-obs-hosted/project.py')

class Isolation(unittest.TestCase):
    def test_only_selected_target_and_identical_configs(self):
        original=p.document()['objects']
        for phase,choose,remove,cfg in (('app',30,31,71),('test',31,30,72)):
            doc,xml=c.isolated(p,phase); objects=doc['objects']
            self.assertEqual(objects[p.ident(1)]['targets'],[p.ident(choose)])
            self.assertEqual(objects[p.ident(choose)]['dependencies'],[])
            for index in (remove,50,51): self.assertNotIn(p.ident(index),objects)
            self.assertEqual(objects[p.ident(cfg)],original[p.ident(cfg)])
            self.assertEqual(objects[p.ident(70)],original[p.ident(70)])
            scheme=ET.fromstring(xml)
            self.assertEqual(scheme.find('BuildAction').attrib['buildImplicitDependencies'],'NO')
            self.assertEqual([r.attrib['BlueprintIdentifier'] for r in scheme.findall('.//BuildableReference')],[p.ident(choose)])
            self.assertIsNone(scheme.find('TestAction'))
    def test_effective_linker_path_only(self):
        host=Path('/own/Debug-iphonesimulator/MadCryptoObsHost.app/MadCryptoObsHost')
        values=dict(TEST_HOST=str(host),BUNDLE_LOADER=str(host),TARGET_BUILD_DIR=str(host.parent.parent),
                    FULL_PRODUCT_NAME=p.TEST+'.xctest',PLATFORM_NAME='iphonesimulator',ARCHS='arm64')
        def call(settings,target=p.TEST): c.test_settings(json.dumps([dict(target=target,buildSettings=settings)]),host,p.TEST)
        call(values)
        for key,value in [('BUNDLE_LOADER','/private/nonmatching'),('TEST_HOST','/tmp/other'),
                          ('OTHER_LDFLAGS','-force_load'),('PLATFORM_NAME','iphoneos'),('ARCHS','x86_64')]:
            with self.assertRaises(ValueError): call(dict(values,**{key:value}))
        with self.assertRaises(ValueError): call(values,p.APP)
    def test_never_boots_or_launches_and_checks_app_on_b_failure(self):
        src=(HERE/'run.py').read_text()
        for term in ("'boot'","'test-without-building'","'build-for-testing'","'launch'"):
            self.assertNotIn(term,src)
        self.assertLess(src.index('if app_identity()!=(host,before)'),src.index('if not test_ok:'))
        self.assertIn('stdout=subprocess.DEVNULL',src)

if __name__=='__main__': unittest.main()
