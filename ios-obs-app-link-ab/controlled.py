"""Isolate the existing authored native targets, without altering link settings."""
import json
import xml.etree.ElementTree as ET

def isolated(project, phase):
    if phase not in ('app','test'): raise ValueError('phase')
    doc=project.document()
    r=project.ident
    choose,remove=(30,31) if phase=='app' else (31,30)
    graph=doc['objects']
    pbx=graph[r(1)]
    pbx['targets']=[r(choose)]
    pbx['attributes'].pop('TargetAttributes')
    graph[r(choose)]['dependencies']=[]
    for index in (remove,50,51): del graph[r(index)]
    name=project.APP if phase=='app' else project.TEST
    product=project.APP+'.app' if phase=='app' else project.TEST+'.xctest'
    scheme=ET.Element('Scheme',version='1.7')
    build=ET.SubElement(scheme,'BuildAction',parallelizeBuildables='NO',buildImplicitDependencies='NO')
    item=ET.SubElement(ET.SubElement(build,'BuildActionEntries'),'BuildActionEntry',
        buildForTesting='NO',buildForRunning='YES',buildForProfiling='NO',buildForArchiving='NO',buildForAnalyzing='NO')
    ET.SubElement(item,'BuildableReference',BuildableIdentifier='primary',BlueprintIdentifier=r(choose),
        BuildableName=product,BlueprintName=name,ReferencedContainer='container:'+project.APP+'.xcodeproj')
    return doc,ET.tostring(scheme,encoding='unicode')+'\n'

def install(project, consumer, phase):
    doc,scheme=isolated(project,phase)
    directory=consumer/(project.APP+'.xcodeproj')
    (directory/'project.pbxproj').write_text('// !$*UTF8*$!\n'+project.serialize(doc)+'\n')
    (directory/'xcshareddata/xcschemes'/('Diagnostic-'+phase+'.xcscheme')).write_text(scheme)

def test_settings(text, expected_host, test_name):
    # The exact effective loader and output from the same B scheme/arguments
    # must match the A path. No external SDK or linker-flag substitutions.
    rows=json.loads(text)
    if not isinstance(rows,list) or len(rows)!=1 or rows[0].get('target')!=test_name:
        raise ValueError('target-row')
    values=rows[0]['buildSettings']
    if (values.get('TEST_HOST')!=str(expected_host) or
        values.get('BUNDLE_LOADER')!=str(expected_host) or
        values.get('TARGET_BUILD_DIR')!=str(expected_host.parent.parent) or
        values.get('FULL_PRODUCT_NAME')!=test_name+'.xctest' or
        values.get('PLATFORM_NAME')!='iphonesimulator' or
        values.get('ARCHS')!='arm64' or
        values.get('OTHER_LDFLAGS','').strip()):
        raise ValueError('settings-delta')
