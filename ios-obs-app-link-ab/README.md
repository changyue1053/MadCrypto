# Build-only iOS hosted linker isolation

Branch-only candidate from public fc297e78fb50a39b538673fe6afca5c13d1ddc7d,
tree 55609bc5f6f65a7ba65321f637c7cb52f63f2b5e. The original OFF/ON
runtime workflow, files, project settings and pins are unchanged. This one
diagnostic job does not rerun the old OFF simulator tests. It builds the same
installed inputs in its own workspace. Exact Xcode 26.2, runner ARM64 and
named owned simulator eligibility continue to be required; simulator is
created but never booted. No app/test execution, installation or upload.

A: a temporary app-only build graph contains the app target only. An otherwise
unchanged app target must link and produce the exact expected signed bundle,
with ARM64 simulator executable, exact embedded identity and required real
SDK and wrapper definitions. Capture a complete signed app fingerprint.

B: replace the temporary graph with only the test target, removing the app
target and its dependency, including implicit build traversal. Keep the
original test target settings and source including TEST_HOST/BUNDLE_LOADER.
Verify the effective settings from the exact isolation arguments (owned host,
target output, architecture, expected test product and no altered link flags)
before building. After either normal build exit, reverify the input hashes,
app identity, signature and complete unchanged bundle. If these do not hold,
report inconclusive rather than attributing failure to the test graph. A B
build success also requires the exact signed simulator test product and actual
foreign bridge imports with no duplicate bundled SDK implementation.

Nonzero exit after A stage isolation is app-only build failure. When A proves
the signed host and B fails with unchanged app + exact effective settings, the
failure is isolated to the test-only build graph, not necessarily one linker
symbol or the root cause of the original full build. B success does not qualify
the normal build-for-testing graph or runtime; original complete acceptance
remains mandatory. Build subprocess output is discarded and time bounded. No
raw paths, settings, names or diagnostics are emitted.

Three portable tests pass. No Xcode/native execution has been performed on
this candidate. One independent source review and explicitly scoped branch
lease are required before a hosted experiment.
