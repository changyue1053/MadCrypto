"""Bound the project/scheme test route to the signed authored products."""
DRIVER='_OBJC_CLASS_$_MadCryptoCohostDriver'
PREFIX=('_madcrypto_','_madobs_','_imobs_')

def symbols(app_defined,test_all,test_undefined,required):
    app=set(app_defined.splitlines())
    test=set(test_all.splitlines())
    unresolved=set(test_undefined.splitlines())
    if not (set(required)|{DRIVER}) <= app:
        raise ValueError('app-linkage')
    if DRIVER not in unresolved or any(x.startswith(PREFIX) for x in test|unresolved):
        raise ValueError('test-driver-only')

class ReceiptRejected(ValueError):
    def __init__(self,reasons):
        super().__init__('receipt-policy')
        self.reasons=tuple(reasons)

def receipt(doc,bind,approved):
    reasons=receipt_issues(doc,bind,approved)
    if reasons: raise ReceiptRejected(reasons)

def receipt_issues(doc,bind,approved):
    # Trusted output of the pinned local Xcode against our authored project.
    # Reject known launch/selection controls outside the one target.
    known_overrides={'EnvironmentVariables','TestingEnvironmentVariables','CommandLineArguments',
                     'OnlyTestIdentifiers','SkipTestIdentifiers','UseDestinationArtifacts',
                     'UITargetAppPath','TestHostPath','TestBundlePath','DependentProductPaths'}
    meta=doc.get('__xctestrun_metadata__',{})
    if not isinstance(meta,dict) or type(meta.get('FormatVersion',1)) is not int or meta.get('FormatVersion',1) not in (1,2):
        return ('receipt-format',)
    if set(doc)&known_overrides: return ('root-override',)
    if meta.get('FormatVersion')==2:
        configs=doc.get('TestConfigurations')
        if not isinstance(configs,list) or len(configs)!=1 or not isinstance(configs[0],dict):
            return ('configuration',)
        if set(configs[0])&known_overrides: return ('configuration-override',)
    try: target=bind.one_target(doc)
    except ValueError as error:
        target_checks={
            'format':'receipt-format','configuration':'configuration',
            'target-set':'target-set','target-id':'target-id','mode':'target-mode',
            'arguments':'target-arguments','alternate-path':'target-alternate-path',
        }
        return (target_checks.get(str(error),'receipt-unknown'),)
    issues=[]
    if (target.get('IsXCTRunnerHostedTestBundle',False) is not False or
        target.get('UITargetAppCommandLineArguments',[])!=[] or
        target.get('UITargetAppEnvironmentVariables',{})!={} or
        any(target.get(k,'')!='' for k in ('BaselinePath','UITargetAppBundleIdentifier',
                                          'TestLanguage','TestRegion')) or
        any(target.get(k,False) is not False for k in ('UITargetAppMainThreadCheckerEnabled',
                                                       'GatherLocalizableStringsData')) or
        target.get('TestExecutionOrdering','') not in ('','alphabetical')):
        issues.append('target-override')
    root='__TESTROOT__/'
    host=root+bind.APP_REL
    if target.get('TestHostPath') not in (host,root+bind.HOST_REL): issues.append('receipt-host')
    if target.get('TestHostBundleIdentifier',bind.APP_ID)!=bind.APP_ID: issues.append('receipt-host-id')
    if target.get('TestBundleIdentifier',bind.TEST_ID)!=bind.TEST_ID: issues.append('receipt-test-id')
    def choices(path):
        names={root+path}
        if path.startswith(bind.APP_REL+'/'):
            names.add('__TESTHOST__/'+path.removeprefix(bind.APP_REL+'/'))
        return names
    if (not isinstance(target.get('TestBundlePath'),str) or
        sum(target['TestBundlePath'] in choices(path) for path in approved)!=1):
        issues.append('receipt-test')
    dep_paths=target.get('DependentProductPaths',[])
    paths={host,root+bind.HOST_REL}
    for path in approved: paths.update(choices(path))
    if not isinstance(dep_paths,list) or any(not isinstance(x,str) or x not in paths for x in dep_paths):
        issues.append('receipt-dependencies')
    defaults=target.get('EnvironmentVariables',{})
    if defaults not in ({},{'OS_ACTIVITY_DT_MODE':'YES'}):
        issues.append('scheme-environment')
    base='__TESTROOT__/Debug-iphonesimulator'
    xcode='__PLATFORMS__/iPhoneSimulator.platform/Developer'
    fixed={
        'DYLD_FRAMEWORK_PATH':{base,base+':'+xcode+'/Library/Frameworks'},
        'DYLD_LIBRARY_PATH':{base,base+':'+xcode+'/usr/lib'},
        'DYLD_INSERT_LIBRARIES':{xcode+'/usr/lib/libXCTestBundleInject.dylib'},
        'XCInjectBundleInto':{root+bind.HOST_REL,'__TESTHOST__/'+bind.APP},
        'XCInjectBundle':{'__TESTBUNDLE__'},
    }
    # The old rule compared XCInjectBundle with the selected bundle path.
    # Keep it identical for a valid bound path; reject malformed plist types
    # before using them to construct a set.
    bundle=target.get('TestBundlePath')
    if isinstance(bundle,str): fixed['XCInjectBundle'].add(bundle)
    env=target.get('TestingEnvironmentVariables',{})
    if not isinstance(env,dict):
        issues.append('loader-shape')
    else:
        labels={'DYLD_FRAMEWORK_PATH':'loader-framework-path',
                'DYLD_LIBRARY_PATH':'loader-library-path',
                'DYLD_INSERT_LIBRARIES':'loader-insert-libraries',
                'XCInjectBundleInto':'loader-inject-host','XCInjectBundle':'loader-inject-bundle'}
        if set(env)-set(fixed): issues.append('loader-other-key')
        for key,label in labels.items():
            if key not in env: continue
            value=env[key]
            if not isinstance(value,str):
                issues.append('loader-value-type')
            elif value not in fixed[key]:
                # Classify only exact fixed native search-path variants;
                # this does not admit any of them for execution.
                alternatives={
                    'DYLD_FRAMEWORK_PATH':{xcode+'/Library/Frameworks:'+base:'-reversed-stock'},
                    'DYLD_LIBRARY_PATH':{xcode+'/usr/lib:'+base:'-reversed-stock',
                                         xcode+'/Library':'-developer-library',
                                         base+':'+xcode+'/Library':'-developer-library-after',
                                         xcode+'/Library:'+base:'-developer-library-before'},
                }
                issues.append(label+alternatives.get(key,{}).get(value,''))
    return tuple(dict.fromkeys(issues))

def products(root,bind):
    if root.resolve(strict=True)!=root: raise ValueError('products-root')
    host=bind.exact(root,bind.HOST_REL)
    approved=[]
    for path in bind.APPROVED_BUNDLES:
        if (root/path).is_symlink() or (root/path).exists(): approved.append(path)
    if not approved: raise ValueError('test-missing')
    def validate(rel,name,bid,kind):
        info=bind.plist(bind.exact(root,rel+'/Info.plist'),65536)
        if (info.get('CFBundleExecutable'),info.get('CFBundleIdentifier'),
            info.get('CFBundlePackageType'))!=(name,bid,kind):
            raise ValueError('product-identity')
    validate(bind.APP_REL,bind.APP,bind.APP_ID,'APPL')
    for path in approved: validate(path,bind.TEST,bind.TEST_ID,'BNDL')
    return host,[bind.exact(root,path+'/'+bind.TEST) for path in approved],approved
