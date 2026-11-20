"""Fail-closed binding to one built Swift package XCTest manifest and product tree."""
import hashlib
import plistlib
from pathlib import Path
CODES=frozenset({
    'artifact-containment','artifact-type','binary-layout','bundle-identity',
    'configuration-disabled','configuration-schema','configuration-set','dependent-products',
    'environment-override','host-identity','implementation-symbols','manifest-bundle',
    'manifest-layout','manifest-schema','manifest-version','platform-host','products-symlink',
    'target-field','target-identity','target-mode','target-override','target-schema',
    'target-set','testing-environment','manifest-size','manifest-parse','products-missing',
    'manifest-missing','manifest-ambiguous','bundle-missing','binary-missing',
    'symbols-crypto','symbols-bridge','symbols-obs',
})
class Rejected(ValueError):
    def __init__(self,code):
        self.code=code if code in CODES else 'unexpected'
        super().__init__(self.code)

NAME='MadCryptoPackageCheckPackageTests'
REQUIRED={'_madcrypto_fixture_main','_madcrypto_session_encrypt',
          '_madcrypto_test_forward','_madcrypto_test_qualification',
          '_madobs_emit_generic_event','_madobs_check_private_batch',
          '_madobs_get_generic_stats','_madobs_stop'}
def contained(root,path):
    resolved=path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)):
        raise Rejected('artifact-containment')
    return resolved
PLATFORMS=Path('/Applications/Xcode_26.2.app/Contents/Developer/Platforms')
HOST='iPhoneSimulator.platform/Developer/Library/Xcode/Agents/xctest'
BUNDLE='Debug-iphonesimulator/'+NAME+'.xctest'
def target(data):
    if not isinstance(data,dict): raise Rejected('manifest-schema')
    meta=data.get('__xctestrun_metadata__',{})
    if not isinstance(meta,dict) or set(meta)-{'FormatVersion'}: raise Rejected('manifest-schema')
    version=meta.get('FormatVersion',1)
    if type(version) is not int: raise Rejected('manifest-schema')
    if version==1:
        if set(data)-{'__xctestrun_metadata__','CodeCoverageBuildableInfos'}!={NAME}: raise Rejected('target-set')
        t=data[NAME]
    elif version==2:
        if set(data)-{'__xctestrun_metadata__','TestConfigurations','CodeCoverageBuildableInfos'}: raise Rejected('manifest-schema')
        configs=data.get('TestConfigurations')
        if not isinstance(configs,list) or len(configs)!=1: raise Rejected('configuration-set')
        c=configs[0]
        if not isinstance(c,dict) or set(c)-{'Name','IsEnabled','TestTargets'}: raise Rejected('configuration-schema')
        if c.get('IsEnabled',True) is not True: raise Rejected('configuration-disabled')
        targets=c.get('TestTargets')
        if not isinstance(targets,list) or len(targets)!=1: raise Rejected('target-set')
        t=targets[0]
    else: raise Rejected('manifest-version')
    if not isinstance(t,dict): raise Rejected('target-schema')
    allowed={'BlueprintName','TestBundlePath','TestHostPath','TestHostBundleIdentifier',
             'TestBundleIdentifier','ProductModuleName','IsAppHostedTestBundle',
             'UseDestinationArtifacts','IsUITestBundle','IsAppHostedTestBundleDisabled','IsSkipped',
             'OnlyTestIdentifiers','SkipTestIdentifiers','EnvironmentVariables','TestingEnvironmentVariables',
             'CommandLineArguments','DependentProductPaths'}
    if set(t)-allowed: raise Rejected('target-field')
    if t.get('BlueprintName')!=NAME: raise Rejected('target-identity')
    for flag in ('UseDestinationArtifacts','IsUITestBundle','IsAppHostedTestBundleDisabled','IsSkipped','IsAppHostedTestBundle'):
        if t.get(flag,False) is not False: raise Rejected('target-mode')
    for key in ('OnlyTestIdentifiers','SkipTestIdentifiers','CommandLineArguments'):
        if t.get(key,[])!=[]: raise Rejected('target-override')
    if t.get('EnvironmentVariables',{})!={}: raise Rejected('environment-override')
    if t.get('TestBundlePath')!='__TESTROOT__/'+BUNDLE: raise Rejected('bundle-identity')
    if t.get('TestHostPath')!='__PLATFORMS__/'+HOST: raise Rejected('host-identity')
    # No alternate application host or arbitrary dylib injection is inferred.
    env=t.get('TestingEnvironmentVariables',{})
    allowed_env={
        'DYLD_FRAMEWORK_PATH':'__TESTROOT__/Debug-iphonesimulator:__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/Frameworks',
        'DYLD_LIBRARY_PATH':'__TESTROOT__/Debug-iphonesimulator:__PLATFORMS__/iPhoneSimulator.platform/Developer/usr/lib',
    }
    if not isinstance(env,dict) or any(k not in allowed_env or v!=allowed_env[k] for k,v in env.items()): raise Rejected('testing-environment')
    deps=t.get('DependentProductPaths',[])
    if not isinstance(deps,list) or len(deps)!=len(set(deps)) or any(x!='__TESTROOT__/'+BUNDLE for x in deps): raise Rejected('dependent-products')
    return t
def identify(products,platforms=PLATFORMS):
    if products.is_symlink(): raise Rejected('products-symlink')
    if not products.is_dir(): raise Rejected('products-missing')
    products=products.resolve(strict=True)
    manifests=list(products.glob('*.xctestrun'))
    if not manifests: raise Rejected('manifest-missing')
    if len(manifests)!=1: raise Rejected('manifest-ambiguous')
    manifest=manifests[0]
    if manifest.is_symlink() or not manifest.is_file(): raise Rejected('manifest-layout')
    with manifest.open('rb') as stream:
        raw=stream.read(1024*1024+1)
    if len(raw)>1024*1024: raise Rejected('manifest-size')
    try: document=plistlib.loads(raw)
    except Exception: raise Rejected('manifest-parse') from None
    target(document)
    if not (products/BUNDLE).exists(): raise Rejected('bundle-missing')
    expected=contained(products,products/BUNDLE)
    if not expected.is_dir(): raise Rejected('manifest-bundle')
    if not (expected/NAME).exists(): raise Rejected('binary-missing')
    binary=contained(products,expected/NAME)
    if not binary.is_file(): raise Rejected('binary-layout')
    # Only the exact pinned platform XCTest facility, never PATH or environment.
    host=platforms/HOST
    if host.is_symlink() or not host.is_file() or host.resolve()!=platforms.resolve()/HOST:
        raise Rejected('platform-host')
    return manifest,binary
def snapshot(products,platforms=PLATFORMS):
    result=fingerprint(products)
    host=platforms/HOST
    result['@pinned-platform-xctest']=('file',hashlib.sha256(host.read_bytes()).hexdigest())
    return result
def fingerprint(products):
    root=products.resolve(strict=True)
    result={}
    for path in sorted(root.rglob('*')):
        rel=str(path.relative_to(root))
        target=contained(root,path)
        if path.is_symlink():
            result[rel]=('link',str(target.relative_to(root)))
        elif path.is_file(): result[rel]=('file',hashlib.sha256(path.read_bytes()).hexdigest())
        elif path.is_dir(): result[rel]=('dir',)
        else: raise Rejected('artifact-type')
    return result
def verify_symbols(text):
    names=set(text.splitlines())
    missing=REQUIRED-names
    if '_madcrypto_session_encrypt' in missing: raise Rejected('symbols-crypto')
    if any(x.startswith('_madcrypto_') for x in missing): raise Rejected('symbols-bridge')
    if missing: raise Rejected('symbols-obs')
