"""Fail-closed binding to one built Swift package XCTest manifest and product tree."""
import hashlib
import plistlib
import re
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
    'manifest-top-fields','manifest-metadata','test-plan-metadata','configuration-name',
    'testing-environment-fields','testing-environment-values','authored-path','authored-bytes',
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
AUTHORED='MadCryptoQualification-reviewed.xctestrun'
V2_FIELDS=frozenset({'__xctestrun_metadata__','TestConfigurations','CodeCoverageBuildableInfos','TestPlan'})
BUNDLE='Debug-iphonesimulator/'+NAME+'.xctest'
def inert_name(value):
    return isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.() -]{0,127}',value) is not None

def target(data):
    if not isinstance(data,dict): raise Rejected('manifest-schema')
    meta=data.get('__xctestrun_metadata__',{})
    if not isinstance(meta,dict) or set(meta)-{'FormatVersion'}: raise Rejected('manifest-metadata')
    version=meta.get('FormatVersion',1)
    if type(version) is not int: raise Rejected('manifest-metadata')
    if version==1:
        if set(data)-{'__xctestrun_metadata__','CodeCoverageBuildableInfos'}!={NAME}: raise Rejected('target-set')
        t=data[NAME]
    elif version==2:
        if set(data)-V2_FIELDS:
            raise Rejected('manifest-top-fields')
        if 'TestPlan' in data:
            plan=data['TestPlan']
            # Documented informational metadata; never used to select or run tests.
            if (not isinstance(plan,dict) or set(plan)!={'Name','IsDefault'} or
                not inert_name(plan['Name']) or type(plan['IsDefault']) is not bool):
                raise Rejected('test-plan-metadata')
        configs=data.get('TestConfigurations')
        if not isinstance(configs,list) or len(configs)!=1: raise Rejected('configuration-set')
        c=configs[0]
        if not isinstance(c,dict) or set(c)-{'Name','IsEnabled','TestTargets'}: raise Rejected('configuration-schema')
        if 'Name' in c and not inert_name(c['Name']): raise Rejected('configuration-name')
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
    if not isinstance(env,dict): raise Rejected('testing-environment')
    if set(env)-allowed_env.keys(): raise Rejected('testing-environment-fields')
    if any(v!=allowed_env[k] for k,v in env.items()): raise Rejected('testing-environment-values')
    deps=t.get('DependentProductPaths',[])
    if not isinstance(deps,list) or len(deps)!=len(set(deps)) or any(x!='__TESTROOT__/'+BUNDLE for x in deps): raise Rejected('dependent-products')
    return t
def authored_plan(document):
    # Treat the generated v2 manifest as evidence only. Unknown top-level
    # metadata remains in the original receipt but is NEVER handed to Xcode.
    if not isinstance(document,dict): raise Rejected('manifest-schema')
    meta=document.get('__xctestrun_metadata__')
    if not isinstance(meta,dict) or type(meta.get('FormatVersion')) is not int or meta['FormatVersion']!=2:
        raise Rejected('manifest-metadata')
    source=target({k:document[k] for k in V2_FIELDS if k in document})
    approved={
        'BlueprintName':NAME,
        'TestBundlePath':'__TESTROOT__/'+BUNDLE,
        'TestHostPath':'__PLATFORMS__/'+HOST,
    }
    # target() checked exact literals/list shape before these are included.
    for key in ('TestingEnvironmentVariables','DependentProductPaths'):
        if source.get(key): approved[key]=source[key]
    output={'__xctestrun_metadata__':{'FormatVersion':2},
            'TestConfigurations':[{'Name':'Qualification','IsEnabled':True,'TestTargets':[approved]}]}
    target(output)
    return plistlib.dumps(output,sort_keys=True)

def _identify(products,platforms,author=False,existing_plan=False):
    if products.is_symlink(): raise Rejected('products-symlink')
    if not products.is_dir(): raise Rejected('products-missing')
    products=products.resolve(strict=True)
    plan=products/AUTHORED
    if existing_plan:
        if not author or plan.is_symlink() or not plan.is_file(): raise Rejected('authored-path')
    elif plan.exists() or plan.is_symlink(): raise Rejected('authored-path')
    manifests=[p for p in products.glob('*.xctestrun') if p!=plan]
    if not manifests: raise Rejected('manifest-missing')
    if len(manifests)!=1: raise Rejected('manifest-ambiguous')
    manifest=manifests[0]
    if manifest.is_symlink() or not manifest.is_file(): raise Rejected('manifest-layout')
    with manifest.open('rb') as stream:
        raw=stream.read(1024*1024+1)
    if len(raw)>1024*1024: raise Rejected('manifest-size')
    try: document=plistlib.loads(raw)
    except Exception: raise Rejected('manifest-parse') from None
    if author: execution=authored_plan(document)
    else: target(document)
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
    if not author: return manifest,binary
    if existing_plan:
        with plan.open('rb') as stream:
            if stream.read(len(execution)+1)!=execution: raise Rejected('authored-bytes')
    else:
        with plan.open('xb') as stream: stream.write(execution)
    return manifest,binary,plan

def identify(products,platforms=PLATFORMS):
    return _identify(products,platforms)

def bind_execution(products,platforms=PLATFORMS,existing_plan=False):
    return _identify(products,platforms,author=True,existing_plan=existing_plan)

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
