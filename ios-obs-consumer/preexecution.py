"""Exact source-independent package/destination discriminants, no raw output."""
import plistlib
import re
from pathlib import Path
def simulator_slice(package):
    root=package.resolve(strict=True)
    data=plistlib.loads((root/'Info.plist').read_bytes())
    entries=data.get('AvailableLibraries')
    if not isinstance(entries,list): raise ValueError('package-layout')
    sim=[x for x in entries if x.get('SupportedPlatform')=='ios' and x.get('SupportedPlatformVariant')=='simulator']
    if len(sim)!=1 or sim[0].get('SupportedArchitectures')!=['arm64']: raise ValueError('package-simulator')
    item=sim[0]
    for key in ('LibraryIdentifier','LibraryPath','HeadersPath'):
        value=item.get(key)
        if not isinstance(value,str) or not value or Path(value).is_absolute() or '..' in Path(value).parts: raise ValueError('package-path')
    folder=root/item['LibraryIdentifier']
    library=(folder/item['LibraryPath']).resolve(strict=True)
    headers=(folder/item['HeadersPath']).resolve(strict=True)
    if not library.is_relative_to(root) or not headers.is_relative_to(root) or not library.is_file() or not headers.is_dir(): raise ValueError('package-containment')
    return library
def destination(text,uuid):
    if len(text)>2*1024*1024 or not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',uuid): raise ValueError('destination-input')
    eligible=text.split('Ineligible destinations',1)[0]
    matches=[]
    for line in eligible.splitlines():
        matches.extend(line for _ in re.finditer(r'\bid:\s*'+re.escape(uuid)+r'\s*[,}]',line))
    if len(matches)!=1 or not re.search(r'\bplatform:\s*iOS Simulator\s*,',matches[0]) or not re.search(r'\barch:\s*arm64\s*,',matches[0]): raise ValueError('destination-eligibility')

OBS_HEADERS=('madobs/runtime.h','madobs/observer.h','madobs/privacy.h','imobs/imobs_c.h')

def digest(path):
    import hashlib
    with path.open('rb') as stream:
        h=hashlib.sha256()
        for block in iter(lambda: stream.read(1024*1024),b''):
            h.update(block)
        return h.hexdigest()

def relocate_obs(installed, destination, headers):
    import shutil
    installed=installed.resolve(strict=True)
    files={'lib/libmadobs_runtime.a':destination}
    files.update({'include/'+name:headers/name for name in OBS_HEADERS})
    fingerprints={}
    for relative,out in files.items():
        source=installed/relative
        if source.resolve(strict=True)!=source or not source.is_file():
            raise ValueError('obs-installed-file')
        out.parent.mkdir(parents=True,exist_ok=True)
        if out.exists() or out.is_symlink(): raise ValueError('obs-consumer-file')
        fingerprints[out]=digest(source)
        shutil.copyfile(source,out)
    verify_inputs(fingerprints)
    return fingerprints

def verify_inputs(fingerprints):
    for path,expected in fingerprints.items():
        if path.resolve(strict=True)!=path or not path.is_file() or digest(path)!=expected:
            raise ValueError('consumer-input-changed')
