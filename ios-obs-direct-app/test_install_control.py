import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
c=load('control',HERE/'install_control.py')
p=load('project',HERE.parent/'ios-obs-hosted/project.py')
g=load('controlled',HERE.parent/'ios-obs-app-link-ab/controlled.py')
from types import SimpleNamespace

class InstallControl(unittest.TestCase):
    def test_metadata_matches_but_no_sdk_input(self):
        doc=c.document(p)['objects']
        old=p.document()['objects']
        self.assertEqual(doc[p.ident(70)],old[p.ident(70)])
        self.assertEqual(doc[p.ident(40)]['files'],[p.ident(20)])
        values=doc[p.ident(71)]['buildSettings']
        self.assertNotEqual(values['PRODUCT_BUNDLE_IDENTIFIER'],p.APP_ID)
        self.assertEqual(set(old[p.ident(71)]['buildSettings'])-set(values),{'EXPORTED_SYMBOLS_FILE','HEADER_SEARCH_PATHS'})
        self.assertEqual(values['OTHER_LDFLAGS'],['$(inherited)','-framework','UIKit'])
        self.assertNotIn('madcrypto_',c.SOURCE)
        self.assertNotIn('madobs_',c.SOURCE)
        proxy=SimpleNamespace(document=lambda:c.document(p),ident=p.ident,APP=p.APP,TEST=p.TEST)
        concrete,xml=g.isolated(proxy,'app')
        self.assertEqual(concrete['objects'][p.ident(1)]['targets'],[p.ident(30)])
        self.assertIsNone(ET.fromstring(xml).find('TestAction'))
    def test_comparison_never_confuses_install_with_runtime(self):
        for (real,tiny),expected in {
            ('installed','installed'):'both-installed',('timeout','timeout'):'both-timeout',
            ('timeout','installed'):'only-control-installed',('installed','timeout'):'only-product-installed',
            ('start','signal'):'neither-installed',('timeout',None):'inconclusive'}.items():
            self.assertEqual(c.compare(real,tiny),expected)
    def test_independent_single_install_after_product_cleanup(self):
        control=(HERE/'install_control.py').read_text()
        run=(HERE/'run.py').read_text()
        self.assertEqual(control.count("installer.invoke(sim+['install'"),1)
        self.assertNotIn("['launch'",control)
        self.assertIn("uuid.lower()==product_uuid.lower()",control)
        self.assertIn("for action in ('shutdown','delete'):",control)
        self.assertLess(run.index("if cleanup: raise Failed('direct-sim-cleanup')"),run.index('comparison.invoke('))
        self.assertIn("if with_control and product_install is not None:",run)
        self.assertIn("if control_status is None: raise Failed('install-comparison-inconclusive')",run)
if __name__=='__main__':unittest.main()
