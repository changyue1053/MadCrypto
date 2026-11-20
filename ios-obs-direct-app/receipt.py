"""Strict simulator-owned direct app receipt checks; no raw diagnostics."""
import json
import os
from pathlib import Path
import re
import stat

NAMES=('testInstalledABIVersion','testInstalledExistingSelftest','testInstalledPrivateFixtureDrain')
UUID=r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}'
MAX=4096

def only_keys(pairs):
    record={}
    for key,val in pairs:
        if key in record: raise ValueError('duplicate')
        record[key]=val
    return record

def pid(text,bundle):
    match=re.fullmatch(re.escape(bundle)+r': ([1-9][0-9]{0,9})\n?',text)
    if not match or int(match[1])>2**31-1: raise ValueError('pid')
    return int(match[1])

def container(text,devices,uuid,kind):
    if kind not in ('app','data') or not re.fullmatch(UUID,uuid): raise ValueError('scope')
    value=text.removesuffix('\n')
    if not value.startswith('/') or len(value)>2048 or any(ord(c)<32 for c in value): raise ValueError('path')
    root=devices.resolve(strict=True)/uuid/'data'/'Containers'
    root=root/('Bundle' if kind=='app' else 'Data')/'Application'
    candidate=Path(value)
    actual=candidate.resolve(strict=True)
    if actual!=candidate or not actual.is_relative_to(root) or not actual.is_dir(): raise ValueError('path')
    parts=actual.relative_to(root).parts
    expected=2 if kind=='app' else 1
    if len(parts)!=expected or not re.fullmatch(UUID,parts[0]): raise ValueError('path-shape')
    if kind=='app' and parts[1]!='MadCryptoObsHost.app': raise ValueError('bundle-name')
    return actual

def verify(data,nonce,launched):
    if len(data)>MAX or not re.fullmatch(r'[0-9a-f]{32}',nonce): raise ValueError('size')
    item=json.loads(data,object_pairs_hook=only_keys)
    if not isinstance(item,dict) or set(item)!={'version','nonce','pid','outcomes'}: raise ValueError('schema')
    if type(item['version']) is not int or item['version']!=1 or item['nonce']!=nonce: raise ValueError('identity')
    if type(item['pid']) is not int or item['pid']!=launched: raise ValueError('pid')
    cases=item['outcomes']
    if not isinstance(cases,dict) or set(cases)!=set(NAMES) or any(cases[n] is not True for n in NAMES):
        raise ValueError('failed-outcome')

def read(path):
    if path.resolve(strict=True)!=path: raise ValueError('receipt-path')
    # Nonblock prevents unexpected special files from stalling the deadline.
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>MAX or info.st_nlink!=1:
            raise ValueError('receipt-file')
        return handle.read(MAX+1)
