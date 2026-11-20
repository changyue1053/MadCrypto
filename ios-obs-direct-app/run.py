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
import secrets
import time
PIN='4af77ffa464a48307e5ff2d95f10b835919d205b'
TREE='3a03801beb18c9601630cc4421b95c2743018dfb'
ORIGIN='https://github.com/changyue1053/MadObs.git'
ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'ios-obs-consumer'
HOSTED=ROOT/'ios-obs-hosted'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod
def module(name,file): return load(name,HOSTED/file)
AB=ROOT/'ios-obs-app-link-ab'
DIRECT=ROOT/'ios-obs-direct-app'
baseline=load('frozen_hosted_runner',HOSTED/'run.py')
run=baseline.run
Failed=baseline.Failed

def isolated_build(args,cwd):
    # Deliberately do not read native output. Distinguish a normal nonzero
    # tool exit from timeout/start/signal, all of which are inconclusive.
    result=subprocess.run(args,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,timeout=1200)
    if result.returncode<0: raise ValueError('build-signal')
    return result.returncode==0

def main(with_control=False):
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
        hosted.create(consumer)
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
        # Own one isolated simulator; no XCTest bundle is built or run.
        runtime='com.apple.CoreSimulator.SimRuntime.iOS-26-2'
        runtimes=json.loads(run(['xcrun','simctl','list','runtimes','available','-j'],'sim-runtime'))
        if not any(r['identifier']==runtime and r['isAvailable'] for r in runtimes['runtimes']): raise Failed('sim-runtime')
        uuid=run(['xcrun','simctl','create','MadCrypto-Obs-Direct-App','com.apple.CoreSimulator.SimDeviceType.iPhone-16',runtime],'sim-create').strip()
        if not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',uuid): raise Failed('sim-id')
        product_install=None
        try:
            control=load('controlled_link',AB/'controlled.py')
            bind=module('hosted_binding','binding.py')
            audit=load('qualification_artifacts',HERE/'artifacts.py')
            derived=work/'derived'
            products=derived/'Build/Products'
            project=['xcodebuild','-project',hosted.APP+'.xcodeproj']
            dest=['-destination','platform=iOS Simulator,id='+uuid,'-destination-timeout','120',
                  '-derivedDataPath',str(derived),'-configuration','Debug']
            def cmd(phase): return project+['-scheme','Diagnostic-'+phase]+dest
            control.install(hosted,consumer,'app')
            try: pre.destination(run(project+['-scheme','Diagnostic-app','-showdestinations'],'direct-destination-query',cwd=consumer),uuid)
            except Exception: raise Failed('direct-destination-eligibility') from None
            smoke=load('direct_receipt',DIRECT/'receipt.py')
            fixture=consumer/'App/fixture.c'
            main=consumer/'App/main.m'
            shutil.copyfile(DIRECT/'main.m',main)
            source_hashes={p:pre.digest(p) for p in (fixture,main,consumer/'App/Bridge.cpp',
                consumer/'App/Entries.c',consumer/'App/FixtureHook.h',consumer/'App/Bridge.h',
                consumer/'App/madcrypto_obs.h', consumer/(hosted.APP+'.xcodeproj')/'project.pbxproj')}
            try: app_ok=isolated_build(cmd('app')+['build'],consumer)
            except Exception: raise Failed('direct-app-build-inconclusive') from None
            if not app_ok: raise Failed('direct-app-build')
            def app_identity():
                host=bind.exact(products,bind.HOST_REL)
                meta=bind.plist(bind.exact(products,bind.APP_REL+'/Info.plist'),65536)
                if (meta.get('CFBundleExecutable'),meta.get('CFBundleIdentifier'),meta.get('CFBundlePackageType'))!=(bind.APP,bind.APP_ID,'APPL'):
                    raise ValueError('app-plist')
                if run(['xcrun','lipo','-archs',str(host)],'ab-app-architecture').strip()!='arm64':
                    raise ValueError('app-architecture')
                bind.verify_platform(run(['xcrun','otool','-l',str(host)],'ab-app-platform'))
                run(['/usr/bin/codesign','--verify','--strict',str(host.parent)],'ab-app-signature')
                defined=set(run(['xcrun','nm','-U','-j',str(host)],'ab-app-nm').splitlines())
                if not (audit.REQUIRED|bind.EXPORTS)<=defined: raise ValueError('app-symbols')
                return host,audit.fingerprint(host.parent)
            try:
                pre.verify_inputs(fingerprints|source_hashes)
                host,before=app_identity()
            except Exception: raise Failed('direct-app-proof') from None
            print('PASS: direct-app-signed-linked',flush=True)
            nonce=secrets.token_hex(16)
            try:
                run(['xcrun','simctl','boot',uuid],'direct-sim-boot',timeout=120)
                run(['xcrun','simctl','bootstatus',uuid,'-b'],'direct-sim-ready',timeout=180)
                device_root=Path.home()/'Library/Developer/CoreSimulator/Devices'
                def locate(phase,kind):
                    return smoke.lookup_container(run,Failed,device_root,uuid,bind.APP_ID,phase,kind)
                installer=load('direct_install_diagnostics',DIRECT/'install_diagnostics.py')
                print('START: direct-app-install',flush=True)
                install_failure=installer.invoke(['xcrun','simctl','install',uuid,str(host.parent)])
                product_install='installed' if install_failure is None else install_failure
                if install_failure is not None:
                    # Emit now, before simulator cleanup can obscure the duration.
                    print('RESULT: direct-app-install-'+install_failure,flush=True)
                    raise Failed('direct-app-install-'+install_failure)
                print('PASS: direct-app-install',flush=True)
                installed=locate('initial','app')
                data=locate('initial','data')
                def installed_identity(phase):
                    if locate(phase,'app')!=installed or locate(phase,'data')!=data or audit.fingerprint(installed)!=before:
                        raise ValueError('installed-app-delta')
                    run(['/usr/bin/codesign','--verify','--strict',str(installed)],'direct-installed-signature',timeout=30)
                installed_identity('prelaunch')
                result=data/'Library/Caches/madcrypto-direct.json'
                partial=result.with_name('madcrypto-direct.partial')
                drain=result.with_name('madcrypto-direct-drain')
                for item in (result,partial,drain):
                    if item.resolve()!=item or item.exists() or item.is_symlink(): raise ValueError('freshness')
                launched=smoke.pid(run(['xcrun','simctl','launch',uuid,bind.APP_ID,nonce],
                                       'direct-app-launch',timeout=60),bind.APP_ID)
                deadline=time.monotonic()+90
                while time.monotonic()<deadline:
                    if result.is_symlink() or partial.is_symlink(): raise ValueError('receipt-alias')
                    if result.exists() and not partial.exists(): break
                    time.sleep(0.25)
                else: raise Failed('direct-receipt-timeout')
                first=smoke.read(result)
                smoke.verify(first,nonce,launched)
                run(['xcrun','simctl','terminate',uuid,bind.APP_ID],'direct-app-terminate',timeout=30)
                if smoke.read(result)!=first or partial.exists() or partial.is_symlink() or drain.exists() or drain.is_symlink():
                    raise ValueError('receipt-delta')
                pre.verify_inputs(fingerprints|source_hashes)
                if app_identity()!=(host,before): raise ValueError('built-app-delta')
                installed_identity('postrun')
            except Failed: raise
            except Exception: raise Failed('direct-receipt-or-artifact') from None
            for name in smoke.NAMES: print('PASS: direct-app-'+name)
            print('PASS: direct-app-runtime-only')
        finally:
            cleanup=False
            for action in ('shutdown','delete'):
                try: run(['xcrun','simctl',action,uuid],'direct-sim-cleanup',timeout=60)
                except Failed:
                    if action=='delete': cleanup=True
            if cleanup: raise Failed('direct-sim-cleanup')
            if with_control and product_install is not None:
                comparison=load('independent_install_control',DIRECT/'install_control.py')
                try:
                    control_status=comparison.invoke(work,uuid,runtime,
                        (hosted,control,bind,pre,smoke,installer,run,Failed))
                except Exception:
                    control_status=None
                    print('RESULT: install-control-only-inconclusive',flush=True)
                print('RESULT: install-comparison-'+comparison.compare(product_install,control_status),flush=True)
                if control_status is None: raise Failed('install-comparison-inconclusive')

if __name__=='__main__':
    try:
        argv=sys.argv[1:]
        if argv not in ([],['--with-install-control']): raise Failed('direct-app-mode')
        main(bool(argv))
    except Failed as error:
        print('FAIL: '+str(error)); sys.exit(1)
    except Exception:
        print('FAIL: direct-app-orchestration'); sys.exit(1)
