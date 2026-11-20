"""App-only controlled evidence: prove the exact dyld export-trie entries."""
import re
import struct
import xml.etree.ElementTree as ET

DRIVER='_OBJC_CLASS_$_MadCryptoCohostDriver'
META='_OBJC_METACLASS_$_MadCryptoCohostDriver'
TARGETS=frozenset({DRIVER,META})
MAX_COMMANDS=1024*1024
MAX_TRIE=8*1024*1024
MAX_TEXT=2*1024*1024

def trie_range(executable):
    """Confirm a real, non-empty dyld export trie before using dyld_info."""
    with executable.open('rb') as stream:
        hdr=stream.read(32)
        if len(hdr)!=32: raise ValueError('mach-header')
        magic,cpu,_,filetype,ncmds,commands,_,_=struct.unpack('<8I',hdr)
        if (magic,cpu,filetype)!=(0xfeedfacf,0x0100000c,2) or not 1<=ncmds<=4096 or not 8<=commands<=MAX_COMMANDS:
            raise ValueError('mach-header')
        table=stream.read(commands)
        stream.seek(0,2); length=stream.tell()
    if len(table)!=commands: raise ValueError('mach-commands')
    offset=0; found=[]
    for _ in range(ncmds):
        if offset+8>len(table): raise ValueError('mach-commands')
        command,size=struct.unpack_from('<II',table,offset)
        if size<8 or size%8 or offset+size>len(table): raise ValueError('mach-commands')
        if command==0x80000033:  # LC_DYLD_EXPORTS_TRIE from mach-o/loader.h
            if size!=16: raise ValueError('mach-exports-command')
            found.append(struct.unpack_from('<II',table,offset+8))
        elif command in (0x22,0x80000022):  # LC_DYLD_INFO[_ONLY]
            if size!=48: raise ValueError('mach-exports-command')
            start,n=struct.unpack_from('<II',table,offset+40)
            if start or n: found.append((start,n))
        offset+=size
    if offset!=len(table) or len(found)!=1: raise ValueError('mach-exports-command')
    start,n=found[0]
    if start<32+commands or not 2<=n<=MAX_TRIE or start+n>length:
        raise ValueError('mach-exports-range')
    return start,n

def classify(output, *, reject_sdk_exports=False):
    if not isinstance(output,str) or len(output)>MAX_TEXT: raise ValueError('export-output')
    lines=output.splitlines()
    if (len(lines)<4 or not lines[0].endswith(':') or lines[1].strip()!='-exports:' or
        lines[2].split()!=['offset','symbol']):
        raise ValueError('export-table')
    seen=set()
    for raw in lines[3:]:
        if not raw.strip(): continue
        words=raw.split()
        if not words: continue
        if reject_sdk_exports and any(word.startswith(('_madcrypto_','_madobs_','_imobs_')) for word in words[1:]):
            raise ValueError('export-sdk-surface')
        matches=TARGETS.intersection(words)
        if matches:
            if (len(matches)!=1 or len(words)!=2 or words[1] not in matches or
                not re.fullmatch(r'0x[0-9a-fA-F]{8,16}',words[0]) or int(words[0],16)==0 or words[1] in seen):
                raise ValueError('export-ambiguous-driver')
            seen.add(words[1])
        elif not (re.fullmatch(r'0x[0-9a-fA-F]{8,16}',words[0]) and len(words)>=2) and words[0]!='[re-export]':
            raise ValueError('export-table')
    return {frozenset():'neither',frozenset({DRIVER}):'class-only',
            frozenset({META}):'metaclass-only',TARGETS:'class-and-metaclass'}[frozenset(seen)]

def isolate(hosted, generated, consumer):
    """Remove the XCTest target; preserve every setting/source of the app."""
    r=hosted.ident
    objects=generated['objects']
    objects[r(1)]['targets']=[r(30)]
    objects[r(1)]['attributes'].pop('TargetAttributes')
    for index in (31,50,51): del objects[r(index)]
    name=hosted.APP
    project=consumer/(name+'.xcodeproj')
    (project/'project.pbxproj').write_text('// !$*UTF8*$!\n'+hosted.serialize(generated)+'\n')
    (project/'xcshareddata/xcschemes'/(name+'.xcscheme')).unlink()
    scheme=ET.Element('Scheme',version='1.7')
    build=ET.SubElement(scheme,'BuildAction',buildImplicitDependencies='NO',parallelizeBuildables='NO')
    item=ET.SubElement(ET.SubElement(build,'BuildActionEntries'),'BuildActionEntry',
        buildForTesting='NO',buildForRunning='YES',buildForProfiling='NO',buildForArchiving='NO',buildForAnalyzing='NO')
    ET.SubElement(item,'BuildableReference',BuildableIdentifier='primary',BlueprintIdentifier=r(30),
        BuildableName=name+'.app',BlueprintName=name,ReferencedContainer='container:'+name+'.xcodeproj')
    (project/'xcshareddata/xcschemes/AppExportsOnly.xcscheme').write_text(ET.tostring(scheme,encoding='unicode')+'\n')
