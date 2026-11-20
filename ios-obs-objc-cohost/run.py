"""Isolated job orchestration. Invoke with python3 -I; no package uploads."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
PIN='4af77ffa464a48307e5ff2d95f10b835919d205b'
TREE='3a03801beb18c9601630cc4421b95c2743018dfb'
ORIGIN='https://github.com/changyue1053/MadObs.git'
ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'ios-obs-consumer'
HOSTED=ROOT/'ios-obs-hosted'
COHOST=ROOT/'ios-obs-objc-cohost'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod
def module(name,file): return load(name,HOSTED/file)
class Failed(Exception): pass
def run(args, stage, cwd=None, env=None, timeout=1200):
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(args,cwd=cwd,env=env,stdout=output,stderr=output,check=True,timeout=timeout,stdin=subprocess.DEVNULL)
            output.seek(0)
            value=output.read(2*1024*1024+1)
            if len(value)>2*1024*1024: raise Failed(stage)
            return value.decode('utf-8')
        except subprocess.CalledProcessError:
            if stage=='consumer-link':
                spec=importlib.util.spec_from_file_location('qualified_diagnostics',HERE/'diagnostics.py')
                diagnostic=importlib.util.module_from_spec(spec); spec.loader.exec_module(diagnostic)
                code,phase,coverage=diagnostic.scan(output)
                if code not in diagnostic.CODES|diagnostic.EARLY_CODES: code='other'
                if phase not in diagnostic.PHASES: phase='none'
                if coverage not in ('complete','truncated'): coverage='truncated'
                suffix=''
                if code=='undefined-symbol':
                    try: suffix='-'+module('hosted_link_diagnostics','link_diagnostics.py').scan(output)
                    except Exception: suffix='-ld-unknown-block-unparsed'
                raise Failed('consumer-link-'+code+'-phase-'+phase+'-'+coverage+suffix) from None
            raise Failed(stage) from None
        except subprocess.TimeoutExpired:
            raise Failed(stage+'-timeout' if stage=='consumer-link' else stage) from None
        except Exception: raise Failed(stage) from None
def main(export_only=False):
    if not sys.flags.isolated: raise Failed('python-isolation')
    if run(['uname','-m'],'host').strip()!='arm64': raise Failed('host')
    if run(['xcodebuild','-version'],'xcode').strip()!='Xcode 26.2\nBuild version 17C52': raise Failed('xcode')
    # Use runner CMake as in the approved MadObs iOS recipe; no tool provisioner.
    version=run(['cmake','--version'],'cmake').splitlines()[0]
    if not re.fullmatch(r'cmake version \d+\.\d+\.\d+',version): raise Failed('cmake')
    base=Path(os.environ['RUNNER_TEMP'])
    if base.is_symlink() or not base.is_dir(): raise Failed('temporary-root')
    base=base.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='madcrypto-obs-',dir=base) as temporary:
        work=Path(temporary)
        # Preparation only: anonymous exact public Git fetch, no inherited credentials/config.
        home=work/'git-home'; home.mkdir()
        clean={'PATH':os.environ['PATH'],'HOME':str(home),'GIT_CONFIG_NOSYSTEM':'1',
               'GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
        obs=work/'obs-producer'; obs.mkdir()
        git=['git','-c','credential.helper=','-c','core.hooksPath=/dev/null']
        run(git+['init',str(obs)],'obs-init',env=clean)
        run(git+['remote','add','origin',ORIGIN],'obs-origin',cwd=obs,env=clean)
        run(git+['fetch','--depth=1','--no-tags','origin',PIN],'obs-fetch',cwd=obs,env=clean)
        run(git+['checkout','--detach','FETCH_HEAD'],'obs-checkout',cwd=obs,env=clean)
        for args,expected in [(['rev-parse','HEAD'],PIN),(['rev-parse','HEAD^{tree}'],TREE),(['remote','get-url','origin'],ORIGIN)]:
            if run(git+args,'obs-pin',cwd=obs,env=clean).strip()!=expected: raise Failed('obs-pin')
        # All network preparation is complete. Cargo is offline; Swift has only local binaries.
        run(['bash','ios-package-check/build.sh'],'crypto-package',cwd=ROOT)
        consumer=work/'consumer'
        hosted=module('hosted_project','project.py')
        graph=load('cohost_project',COHOST/'project.py').create(hosted,consumer)
        artifacts=consumer/'Inputs'
        artifacts.mkdir()
        crypto=ROOT/'build/ios-package-check/MadCrypto.xcframework'
        shutil.move(str(crypto),artifacts/'MadCrypto.xcframework')
        # Remove producer outputs so consumer cannot silently link Rust build artifacts.
        shutil.rmtree(ROOT/'build/ios-package-check/rust')
        sdk=run(['xcrun','--sdk','iphonesimulator','--show-sdk-path'],'sdk').strip()
        if run(['xcrun','--sdk','iphonesimulator','--show-sdk-version'],'sdk').strip()!='26.2': raise Failed('sdk')
        sdk=Path(sdk)
        if not (sdk/'usr/include/zlib.h').is_file() or not (sdk/'usr/lib/libz.tbd').is_file(): raise Failed('sdk-zlib')
        build=work/'obs-build'; stage=work/'obs-stage'
        run(['cmake','-S',str(obs),'-B',str(build),'-G','Xcode',
             '-DCMAKE_SYSTEM_NAME=iOS','-DCMAKE_OSX_SYSROOT='+str(sdk),
             '-DCMAKE_OSX_ARCHITECTURES=arm64','-DCMAKE_OSX_DEPLOYMENT_TARGET=16.0',
             '-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO','-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED=NO',
             '-DCMAKE_INSTALL_PREFIX='+str(stage),'-DBUILD_TESTING=OFF','-DMADOBS_BUILD_RUNTIME=ON',
             '-DMADOBS_BUILD_SHARED=OFF','-DMADOBS_BUILD_JNI=OFF','-DMADOBS_PACKAGE_BORINGSSL=OFF',
             '-DIMOBS_SAN=','-DIMOBS_BORINGSSL_ROOT=','-DIMOBS_BORINGSSL_INCLUDE=','-DIMOBS_BORINGSSL_CRYPTO_LIB=',
             '-DZLIB_INCLUDE_DIR='+str(sdk/'usr/include'),'-DZLIB_LIBRARY='+str(sdk/'usr/lib/libz.tbd')],'obs-configure')
        run(['cmake','--build',str(build),'--config','Release','--target','imobs_core','--parallel','3'],'obs-build')
        run(['cmake','--install',str(build),'--config','Release'],'obs-install')
        relocated=work/'relocated-obs'; stage.rename(relocated)
        shutil.rmtree(obs); shutil.rmtree(build)
        archive=relocated/'lib/libmadobs_runtime.a'
        if run(['xcrun','lipo','-archs',str(archive)],'obs-architecture').strip()!='arm64': raise Failed('obs-architecture')
        spec=importlib.util.spec_from_file_location('qualified_preexecution',HERE/'preexecution.py')
        pre=importlib.util.module_from_spec(spec); spec.loader.exec_module(pre)
        obs_archive=artifacts/'libmadobs_runtime.a'
        crypto_archive=artifacts/'libmadcrypto_ffi.a'
        try:
            fingerprints=pre.relocate_obs(relocated,obs_archive,artifacts/'ObsHeaders')
            source=pre.simulator_slice(artifacts/'MadCrypto.xcframework')
            headers=artifacts/'CryptoHeaders'; headers.mkdir()
            for source_file,destination in ((source,crypto_archive),
                    (source.parent/'Headers/madcrypto.h',headers/'madcrypto.h')):
                if source_file.resolve(strict=True)!=source_file or not source_file.is_file():
                    raise ValueError('installed-file')
                fingerprints[destination]=pre.digest(source_file)
                shutil.copyfile(source_file,destination)
            pre.verify_inputs(fingerprints)
        except Exception: raise Failed('installed-simulator-slice') from None
        shutil.rmtree(relocated)
        shutil.rmtree(artifacts/'MadCrypto.xcframework')
        for library in (crypto_archive,obs_archive):
            if run(['xcrun','lipo','-archs',str(library)],'installed-simulator-architecture').strip()!='arm64':
                raise Failed('installed-simulator-architecture')
        print('PASS: installed-simulator-slices')
        # No physical-device action: the optional Obs package is simulator-only.
        runtime='com.apple.CoreSimulator.SimRuntime.iOS-26-2'
        runtimes=json.loads(run(['xcrun','simctl','list','runtimes','available','-j'],'sim-runtime'))
        if not any(r['identifier']==runtime and r['isAvailable'] for r in runtimes['runtimes']): raise Failed('sim-runtime')
        uuid=run(['xcrun','simctl','create','MadCrypto-Obs-ObjC-Cohost','com.apple.CoreSimulator.SimDeviceType.iPhone-16',runtime],'sim-create').strip()
        if not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',uuid): raise Failed('sim-id')
        env={k:v for k,v in os.environ.items() if k not in
             ('SDKROOT','PYTHONPATH','DYLD_LIBRARY_PATH','DYLD_INSERT_LIBRARIES','DYLD_FRAMEWORK_PATH')
             and not k.startswith(('SIMCTL_CHILD_','DYLD_','LD_','XCTest','XCInject'))}
        if export_only:
            try:
                only=load('cohost_app_exports',COHOST/'app_exports.py')
                only.isolate(hosted,graph,consumer)
                bind=module('hosted_binding','binding.py')
                audit=load('qualification_artifacts',HERE/'artifacts.py')
                project=['xcodebuild','-project',hosted.APP+'.xcodeproj','-scheme','AppExportsOnly']
                derived=work/'exports-derived'
                dest=['-destination','platform=iOS Simulator,id='+uuid,'-destination-timeout','120',
                      '-derivedDataPath',str(derived),'-configuration','Debug',
                      'ARCHS=arm64','ONLY_ACTIVE_ARCH=YES','ENABLE_DEBUG_DYLIB=NO',
                      'CODE_SIGNING_ALLOWED=YES','CODE_SIGN_IDENTITY=-','CODE_SIGNING_REQUIRED=NO']
                try: pre.destination(run(project+['-showdestinations'],'exports-destination-query',cwd=consumer,env=env),uuid)
                except Exception: raise Failed('exports-destination-eligibility') from None
                source_hashes={p:pre.digest(p) for root in (consumer/'App',consumer/(hosted.APP+'.xcodeproj'))
                               for p in root.rglob('*') if p.is_file()}
                run(project+dest+['build'],'exports-app-only-build',cwd=consumer,env=env,timeout=1200)
                products=derived/'Build/Products'
                binary=bind.exact(products,bind.HOST_REL)
                metadata=bind.plist(bind.exact(products,bind.APP_REL+'/Info.plist'),65536)
                if (metadata.get('CFBundleExecutable'),metadata.get('CFBundleIdentifier'),
                    metadata.get('CFBundlePackageType'))!=(bind.APP,bind.APP_ID,'APPL'):
                    raise Failed('exports-app-identity')
                if run(['xcrun','lipo','-archs',str(binary)],'exports-app-architecture').strip()!='arm64':
                    raise Failed('exports-app-architecture')
                bind.verify_platform(run(['xcrun','otool','-l',str(binary)],'exports-app-platform'))
                linked=run(['xcrun','otool','-L',str(binary)],'exports-app-loads').lower()
                if any(n in linked for n in ('madobsruntime.framework','libmadobs','madcrypto.framework',
                                             'libmadcrypto','.debug.dylib')):
                    raise Failed('exports-app-loads')
                run(['/usr/bin/codesign','--verify','--strict',str(binary.parent)],'exports-app-signature')
                pre.verify_inputs(fingerprints|source_hashes)
                before=audit.fingerprint(binary.parent)
                try: only.trie_range(binary)
                except Exception: raise Failed('exports-trie-unavailable') from None
                output=run(['xcrun','dyld_info','-exports',str(binary)],'exports-trie-reader',timeout=60)
                try: outcome=only.classify(output)
                except Exception: raise Failed('exports-trie-inconclusive') from None
                pre.verify_inputs(fingerprints|source_hashes)
                if audit.fingerprint(binary.parent)!=before: raise Failed('exports-app-changed')
                print('RESULT: objc-app-exports-'+outcome,flush=True)
                if outcome!='class-and-metaclass': raise Failed('exports-app-driver-incomplete')
                print('PASS: objc-app-exports-only',flush=True)
                return
            finally:
                run(['xcrun','simctl','delete',uuid],'exports-sim-delete',timeout=60)
        try:
            run(['xcrun','simctl','boot',uuid],'sim-boot',timeout=120)
            run(['xcrun','simctl','bootstatus',uuid,'-b'],'sim-ready',timeout=180)
            derived=work/'derived'; result=work/'tests.xcresult'
            project=['xcodebuild','-project',hosted.APP+'.xcodeproj','-scheme',hosted.APP]
            args=['-destination','platform=iOS Simulator,id='+uuid,'-destination-timeout','120',
                  '-derivedDataPath',str(derived),'-configuration','Debug','-parallel-testing-enabled','NO',
                  'ARCHS=arm64','ONLY_ACTIVE_ARCH=YES','ENABLE_DEBUG_DYLIB=NO',
                  'CODE_SIGNING_ALLOWED=YES','CODE_SIGN_IDENTITY=-','CODE_SIGNING_REQUIRED=NO']
            destinations=run(project+['-showdestinations'],'cohost-destination-query',cwd=consumer,env=env)
            try: pre.destination(destinations,uuid)
            except Exception: raise Failed('cohost-destination-eligibility') from None
            source_hashes={p:pre.digest(p) for folder in (consumer/'App',consumer/'Tests')
                           for p in folder.rglob('*') if p.is_file()}
            for p in (consumer/(hosted.APP+'.xcodeproj')).rglob('*'):
                if p.is_file(): source_hashes[p]=pre.digest(p)
            run(project+args+['build-for-testing'],'consumer-link',cwd=consumer,env=env)
            print('PASS: objc-cohost-build-for-testing',flush=True)
            bind=module('hosted_binding','binding.py')
            audit=load('qualification_artifacts',HERE/'artifacts.py')
            proof=load('cohost_proof',COHOST/'proof.py')
            products=derived/'Build/Products'
            def identity():
                pre.verify_inputs(fingerprints|source_hashes)
                host,tests,approved=proof.products(products,bind)
                receipts=list(products.glob('*.xctestrun'))
                if len(receipts)!=1 or receipts[0].is_symlink() or not receipts[0].is_file():
                    raise ValueError('receipt-path')
                try: proof.receipt(bind.plist(receipts[0]),bind,approved)
                except Exception: raise Failed('objc-cohost-receipt-policy') from None
                for binary in (host,*tests):
                    if run(['xcrun','lipo','-archs',str(binary)],'cohost-product-architecture').strip()!='arm64':
                        raise ValueError('architecture')
                    bind.verify_platform(run(['xcrun','otool','-l',str(binary)],'cohost-product-platform'))
                    run(['/usr/bin/codesign','--verify','--strict',str(binary.parent)],'cohost-product-signature')
                    loads=run(['xcrun','otool','-L',str(binary)],'cohost-loads').lower()
                    if any(n in loads for n in ('madobsruntime.framework','libmadobs','madcrypto.framework',
                                                'libmadcrypto','.debug.dylib')):
                        raise ValueError('sdk-dynamic-load')
                defined=run(['xcrun','nm','-U','-j',str(host)],'cohost-nm-app')
                for test in tests:
                    proof.symbols(defined,run(['xcrun','nm','-j',str(test)],'cohost-nm-test'),
                                  run(['xcrun','nm','-u','-j',str(test)],'cohost-nm-import'),audit.REQUIRED)
                selected=receipts[0]
                if selected.resolve(strict=True)!=selected: raise ValueError('receipt-canonical')
                return selected,audit.fingerprint(products)
            try: selected,before=identity()
            except Failed: raise
            except Exception: raise Failed('objc-cohost-artifact-binding') from None
            # xctestrun consumption is explicit; no scheme rediscovery or
            # alternate plan. This action cannot rebuild the verified app.
            run(['xcodebuild','-xctestrun',str(selected),'-destination','platform=iOS Simulator,id='+uuid,
                 '-destination-timeout','120','-parallel-testing-enabled','NO',
                 '-resultBundlePath',str(result),'test-without-building'],
                'cohost-tests',cwd=consumer,env=env)
            try:
                if identity()!=(selected,before): raise ValueError('artifact-change')
            except Exception: raise Failed('objc-cohost-artifact-changed') from None
            run([sys.executable,'-I',str(HERE/'results.py'),str(result)],'named-results')
        finally:
            failed=False
            for action in ['shutdown','delete']:
                try: run(['xcrun','simctl',action,uuid],'sim-cleanup',timeout=60)
                except Failed: failed=True
            if failed: raise Failed('sim-cleanup')
        print('PASS: independent-objc-app-owned-ios-obs-three-tests')
if __name__=='__main__':
    try:
        if sys.argv[1:] not in ([],['--app-exports-only']): raise Failed('cohost-run-mode')
        main(bool(sys.argv[1:]))
    except Failed as error:
        print('FAIL: '+str(error)); sys.exit(1)
    except Exception:
        print('FAIL: orchestration-input'); sys.exit(1)
