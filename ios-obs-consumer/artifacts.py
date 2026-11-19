"""Fail-closed binding to one built Swift package XCTest manifest and product tree."""
import hashlib
import plistlib
from pathlib import Path
NAME='MadCryptoPackageCheckPackageTests'
REQUIRED={'_madcrypto_fixture_main','_madcrypto_session_encrypt',
          '_madcrypto_test_forward','_madcrypto_test_qualification',
          '_madobs_emit_generic_event','_madobs_check_private_batch',
          '_madobs_get_generic_stats','_madobs_stop'}
def contained(root,path):
    resolved=path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)):
        raise ValueError('artifact-containment')
    return resolved
PLATFORMS=Path('/Applications/Xcode_26.2.app/Contents/Developer/Platforms')
HOST='iPhoneSimulator.platform/Developer/Library/Xcode/Agents/xctest'
BUNDLE='Debug-iphonesimulator/'+NAME+'.xctest'
def target(data):
    if not isinstance(data,dict): raise ValueError('manifest-schema')
    meta=data.get('__xctestrun_metadata__',{})
    if not isinstance(meta,dict) or set(meta)-{'FormatVersion'}: raise ValueError('manifest-schema')
    version=meta.get('FormatVersion',1)
    if type(version) is not int: raise ValueError('manifest-schema')
    if version==1:
        if set(data)-{'__xctestrun_metadata__','CodeCoverageBuildableInfos'}!={NAME}: raise ValueError('target-set')
        t=data[NAME]
    elif version==2:
        if set(data)-{'__xctestrun_metadata__','TestConfigurations','CodeCoverageBuildableInfos'}: raise ValueError('manifest-schema')
        configs=data.get('TestConfigurations')
        if not isinstance(configs,list) or len(configs)!=1: raise ValueError('configuration-set')
        c=configs[0]
        if not isinstance(c,dict) or set(c)-{'Name','IsEnabled','TestTargets'}: raise ValueError('configuration-schema')
        if c.get('IsEnabled',True) is not True: raise ValueError('configuration-disabled')
        targets=c.get('TestTargets')
        if not isinstance(targets,list) or len(targets)!=1: raise ValueError('target-set')
        t=targets[0]
    else: raise ValueError('manifest-version')
    if not isinstance(t,dict): raise ValueError('target-schema')
    allowed={'BlueprintName','TestBundlePath','TestHostPath','TestHostBundleIdentifier',
             'TestBundleIdentifier','ProductModuleName','IsAppHostedTestBundle',
             'UseDestinationArtifacts','IsUITestBundle','IsAppHostedTestBundleDisabled','IsSkipped',
             'OnlyTestIdentifiers','SkipTestIdentifiers','EnvironmentVariables','TestingEnvironmentVariables',
             'CommandLineArguments','DependentProductPaths'}
    if set(t)-allowed: raise ValueError('target-field')
    if t.get('BlueprintName')!=NAME: raise ValueError('target-identity')
    for flag in ('UseDestinationArtifacts','IsUITestBundle','IsAppHostedTestBundleDisabled','IsSkipped','IsAppHostedTestBundle'):
        if t.get(flag,False) is not False: raise ValueError('target-mode')
    for key in ('OnlyTestIdentifiers','SkipTestIdentifiers','CommandLineArguments'):
        if t.get(key,[])!=[]: raise ValueError('target-override')
    if t.get('EnvironmentVariables',{})!={}: raise ValueError('environment-override')
    if t.get('TestBundlePath')!='__TESTROOT__/'+BUNDLE: raise ValueError('bundle-identity')
    if t.get('TestHostPath')!='__PLATFORMS__/'+HOST: raise ValueError('host-identity')
    # No alternate application host or arbitrary dylib injection is inferred.
    env=t.get('TestingEnvironmentVariables',{})
    allowed_env={
        'DYLD_FRAMEWORK_PATH':'__TESTROOT__/Debug-iphonesimulator:__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/Frameworks',
        'DYLD_LIBRARY_PATH':'__TESTROOT__/Debug-iphonesimulator:__PLATFORMS__/iPhoneSimulator.platform/Developer/usr/lib',
    }
    if not isinstance(env,dict) or any(k not in allowed_env or v!=allowed_env[k] for k,v in env.items()): raise ValueError('testing-environment')
    deps=t.get('DependentProductPaths',[])
    if not isinstance(deps,list) or len(deps)!=len(set(deps)) or any(x!='__TESTROOT__/'+BUNDLE for x in deps): raise ValueError('dependent-products')
    return t
def identify(products,platforms=PLATFORMS):
    if products.is_symlink(): raise ValueError('products-symlink')
    products=products.resolve(strict=True)
    manifests=list(products.glob('*.xctestrun'))
    if len(manifests)!=1 or manifests[0].is_symlink(): raise ValueError('manifest-layout')
    manifest=manifests[0]
    target(plistlib.loads(manifest.read_bytes()))
    expected=contained(products,products/BUNDLE)
    if not expected.is_dir(): raise ValueError('manifest-bundle')
    binary=contained(products,expected/NAME)
    if not binary.is_file(): raise ValueError('binary-layout')
    # Only the exact pinned platform XCTest facility, never PATH or environment.
    host=platforms/HOST
    if host.is_symlink() or not host.is_file() or host.resolve()!=platforms.resolve()/HOST:
        raise ValueError('platform-host')
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
        else: raise ValueError('artifact-type')
    return result
def verify_symbols(text):
    names=set(text.splitlines())
    if not REQUIRED.issubset(names): raise ValueError('implementation-symbols')
