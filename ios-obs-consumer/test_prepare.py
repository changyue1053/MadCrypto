import unittest
from pathlib import Path
from prepare import transform
class Preparation(unittest.TestCase):
    def setUp(self):
        self.original=(Path(__file__).resolve().parents[1]/'tests/obs_adapter.c').read_bytes()
    def test_reversible_only_hook_and_entry(self):
        out=transform(self.original)
        self.assertIn('#ifdef NDEBUG\n#error', out)
        restored=out.split('#include "Bridge.h"\n',1)[1].replace('int madcrypto_fixture_main(void) {','int main(void) {').replace('  assert(madcrypto_test_forward(event) == 1);\n','')
        self.assertEqual(restored.encode(),self.original)
        self.assertEqual(out.count('assert(madcrypto_test_forward(event) == 1);'),1)
    def test_mutation_rejected(self):
        for change in [b'', self.original+b'\n', self.original.replace(b'"y"',b'"z"'), self.original.replace(b'  received++;',b''), self.original.replace(b'int main',b'int other')]:
            with self.assertRaises(ValueError): transform(change)
    def test_admission_is_not_void_observer(self):
        source=Path(__file__).with_name('Bridge.cpp').read_text()
        self.assertIn('madobs_emit_generic_event(active->runtime, &clean) != MADOBS_OK',source)
        self.assertNotIn('madobs_observer_emit(',source)
        self.assertIn('stats.enqueued==1 && stats.drained==1',source)
    def test_privacy_boundary_source(self):
        source=Path(__file__).with_name('Bridge.cpp').read_text()
        checks=['e->sdk_id != 42', 'e->sdk_version != 0x000100', 'e->event_id != 1',
                'e->monotonic_ns != 123', 'e->attribute_count != 0', 'e->reserved != 0',
                'for (const auto &a : e->attributes) if (a.key || a.enum_value) return 0;']
        sanitize='madobs_sanitize_event(&active->policy, e, &clean)'
        for check in checks:
            self.assertIn(check,source)
            self.assertLess(source.index(check),source.index(sanitize))
        for check in ['clean.monotonic_ns != 0', 'clean.attribute_count != 0',
                      'clean.sdk_id != 42', 'clean.sdk_version != 0x000100',
                      'clean.event_id != 1', 'clean.reserved != 0']:
            self.assertIn(check,source)
            self.assertLess(source.index(check),source.index('madobs_emit_generic_event('))
        self.assertNotIn('madobs_emit_generic_event(active->runtime, e)',source)
if __name__=='__main__': unittest.main()
