"""Bounded, fixed-label diagnosis for a failed native link only."""
import re

MAX_BYTES=8*1024*1024
MAX_RECORDS=20000
MAX_LINE=8192
TARGETS={b'MadCryptoObsHost':'app',b'MadCryptoObsHostTests':'test'}
BRIDGE=frozenset({b'_madcrypto_host_abi',b'_madcrypto_host_selftest',b'_madcrypto_test_qualification'})
HEADER=re.compile(rb'^Undefined symbols for architecture (arm64|arm64e|x86_64):$')
FOOTER=re.compile(rb'^ld: symbol\(s\) not found for architecture (arm64|arm64e|x86_64)$')
COMMAND=re.compile(rb"^Ld [^\r\n]+ \(in target '([A-Za-z][A-Za-z0-9]{0,80})' from project 'MadCryptoObsHost'\)$")
SYMBOL=re.compile(rb'^\s*"([A-Za-z0-9_$./@+-]{1,1024})", referenced from:\s*$')
SYSTEM=re.compile(rb'^_(?:OBJC_(?:CLASS|METACLASS)_\$_|swift_|objc_|Sec|CF|dispatch_|pthread_|os_|inflate|deflate|iconv|res_|getaddrinfo|_Z)')
SYSTEM_EXACT={b'_malloc',b'_calloc',b'_free',b'_realloc',b'_memcpy',b'_memset',b'_memcmp',b'_abort'}

def count(n):
    return 'zero' if not n else 'one' if n==1 else 'two-three' if n<=3 else 'four-plus'

def scan(stream):
    stream.seek(0,2)
    size=stream.tell()
    if size>MAX_BYTES: return 'ld-unknown-block-truncated'
    stream.seek(0)
    summary=False
    context='unknown'
    failed=[]
    other_failed=False
    blocks=[]
    active=None
    for _ in range(MAX_RECORDS):
        line=stream.readline(MAX_LINE+1)
        if len(line)>MAX_LINE: return 'ld-unknown-block-truncated'
        if not line: break
        record=line.strip()
        if record==b'The following build commands failed:':
            if summary: return 'ld-unknown-block-ambiguous'
            summary=True
            continue
        if summary:
            if record.startswith(b'Ld '):
                match=COMMAND.fullmatch(record)
                failed.append(TARGETS.get(match[1],'unknown') if match else 'unknown')
            elif record and record!=b'(1 failure)':
                other_failed=True
            continue
        if record.startswith(b'Ld '):
            if active is not None: return 'ld-unknown-block-ambiguous'
            match=COMMAND.fullmatch(record)
            context=TARGETS.get(match[1],'unknown') if match else 'unknown'
        elif re.match(rb'^(?:CompileC|SwiftCompile|SwiftEmitModule|ScanDependencies|CodeSign|Libtool|PhaseScriptExecution) ',record):
            if active is not None: return 'ld-unknown-block-ambiguous'
            context='unknown'
        header=HEADER.fullmatch(record)
        if header:
            if active is not None: return 'ld-unknown-block-ambiguous'
            active=(context,header[1],set())
            continue
        if active is not None:
            footer=FOOTER.fullmatch(record)
            if footer:
                if footer[1]!=active[1]: return 'ld-unknown-block-unparsed'
                blocks.append(active)
                active=None
                continue
            match=SYMBOL.fullmatch(line.rstrip(b'\r\n'))
            if match: active[2].add(match[1])
            elif record.startswith(b'"'): return 'ld-unknown-block-unparsed'
    else:
        if stream.tell()<size: return 'ld-unknown-block-truncated'
    if other_failed: return 'ld-unknown-block-ambiguous'
    if len(failed)!=1:
        return 'ld-unknown-block-ambiguous' if len(failed)>1 else 'ld-unknown-block-no-summary'
    target=failed[0]
    if target=='unknown': return 'ld-unknown-block-unparsed'
    if active is not None: return 'ld-'+target+'-block-incomplete'
    if len(blocks)!=1: return 'ld-'+target+'-block-'+('ambiguous' if blocks else 'unparsed')
    source,_,names=blocks[0]
    if source!=target or not names:
        return 'ld-'+target+'-block-unparsed'
    bridge=names&BRIDGE
    other=names-BRIDGE
    groups=set()
    for symbol in other:
        if symbol.startswith((b'_madcrypto_',b'_madobs_',b'_imobs_')): groups.add('sdk')
        elif symbol in SYSTEM_EXACT or SYSTEM.match(symbol): groups.add('system')
        else: groups.add('unknown')
    bridge_label='all' if bridge==BRIDGE else 'partial' if bridge else 'none'
    group='none' if not groups else next(iter(groups)) if len(groups)==1 else 'mixed'
    return 'ld-'+target+'-bridge-'+bridge_label+'-other-'+group+'-count-'+count(len(names))
