"""Consume only the unchanged original gate's verified relocated archive."""
import argparse,hashlib,json,platform,re,shutil,subprocess,tempfile,zipfile
from pathlib import Path
from package_check import apk,elf,LIB
from toolchain import receipts
ROOT=Path(__file__).resolve().parents[1]
def run(args,stage,capture=False):
    print('START: '+stage,flush=True)
    with tempfile.TemporaryFile() as log:
        try:
            subprocess.run([str(x) for x in args],stdout=log,stderr=log,check=True,timeout=300)
            value=None
            if capture:
                log.seek(0);data=log.read(4*1024*1024+1)
                if len(data)>4*1024*1024:raise ValueError('bound')
                value=data.decode()
        except Exception:
            print('FAIL: '+stage,flush=True);raise RuntimeError('packaging failure') from None
    print('PASS: '+stage,flush=True);return value

def verify_package(package,manifest,sha):
    if manifest.get('source_commit')!=sha or manifest.get('target')!='aarch64-linux-android' or manifest.get('api')!=23 or manifest.get('ndk')!='28.2.13676358' or manifest.get('rust')!='1.100.0':raise ValueError('source/tool identity')
    if manifest.get('android_execution') is not False or manifest.get('redistribution') is not False:raise ValueError('scope')
    paths={'include/madcrypto.h','lib/libmadcrypto_ffi.a','notices/LICENSE','notices/THIRD_PARTY.md'}
    if set(manifest.get('files',{}))!=paths:raise ValueError('manifest files')
    for name in paths:
        p=package/name
        if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(package.resolve()):raise ValueError('package path')
        if hashlib.sha256(p.read_bytes()).hexdigest()!=manifest['files'][name]:raise ValueError('package hash')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--sdk',required=True);sdk=Path(parser.parse_args().sdk).resolve()
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise ValueError('host')
    receipts(sdk)
    original=ROOT/'build/android-package-check';package=original/'relocated-sdk'
    sha=run(['git','-C',ROOT,'rev-parse','HEAD'],'source-identity',True).strip()
    verify_package(package,json.loads((original/'manifest.json').read_text()),sha)
    ndk=sdk/'ndk/28.2.13676358';tools=ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin';cc=tools/'aarch64-linux-android23-clang';bt=sdk/'build-tools/35.0.0';android=sdk/'platforms/android-35/android.jar'
    for path in (cc,bt/'aapt2',bt/'zipalign',android):
        if not path.is_file():raise ValueError('tool missing')
    base=ROOT/'build/android-apk';base.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as temporary:
        work=Path(temporary);copied=work/'relocated SDK';shutil.copytree(package,copied)
        verify_package(copied,json.loads((original/'manifest.json').read_text()),sha)
        source=work/'activity.c';shutil.copyfile(ROOT/'android-apk/activity.c',source)
        library=work/'libmadcrypto_preview.so'
        # Verification target is the SAME archived bytes, no recompilation/flag fallback.
        run([cc,'-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared','-I',copied/'include',source,copied/'lib/libmadcrypto_ffi.a','-ldl','-lm','-Wl,--no-undefined','-Wl,-z,defs','-Wl,-z,max-page-size=16384','-Wl,-z,common-page-size=16384','-Wl,-soname,libmadcrypto_preview.so','-o',library],'static-to-shared-no-fallback')
        dynamic=run([tools/'llvm-nm','--dynamic','--defined-only',library],'dynamic-entry',True)
        if not re.search(r'(?m)^[0-9a-fA-F]+ T ANativeActivity_onCreate$',dynamic):raise ValueError('entry')
        symbols=run([tools/'llvm-nm','--defined-only','--extern-only',library],'implementation-definition',True)
        if not re.search(r'(?m)^[0-9a-fA-F]+ [Tt] madcrypto_abi_version$',symbols):raise ValueError('ABI implementation')
        tags=run([tools/'llvm-readelf','-d',library],'dynamic-dependencies',True)
        needed=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',tags)
        if not needed or not set(needed)<={'libc.so','libm.so','libdl.so'} or 'TEXTREL' in tags:raise ValueError('dependencies or relocations')
        payload=library.read_bytes();elf(payload)
        output=work/'unsigned.apk'
        run([bt/'aapt2','link','-I',android,'--manifest',ROOT/'android-apk/AndroidManifest.xml','--min-sdk-version','23','--target-sdk-version','35','-o',output],'manifest-link')
        with zipfile.ZipFile(output,'a') as archive:archive.writestr(LIB,payload,compress_type=zipfile.ZIP_STORED)
        aligned=work/'aligned-unsigned.apk'
        run([bt/'zipalign','-P','16','-f','4',output,aligned],'zip-align')
        run([bt/'zipalign','-c','-P','16','-v','4',aligned],'zip-check')
        apk(aligned,payload)
        print('PASS: unsigned native APK ZIP/ELF packaging; application and crypto runtime NOT RUN',flush=True)
if __name__=='__main__':
    try:main()
    except Exception:print('FAIL: android-apk-preview');raise SystemExit(1) from None
