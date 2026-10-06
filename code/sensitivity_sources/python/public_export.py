import io
import zipfile

from io_boundary import canonical,identity,require,write_new,read_exact
from protected_sink import bounded_public


def export_new_public(sink):
    require(sink.closed,'COMPLETION_REQUIRED_FOR_PUBLIC_EXPORT')
    files={}
    for name,entry in sorted(sink.entries.items()):
        if entry['visibility']=='PUBLIC_AGGREGATES':
            require(sink.allowed[name] is False,'PRIVATE_EXPORT_FORBIDDEN')
            raw=sink.read_new(name);bounded_public(raw);files[entry['relative_path']]=raw
    require(len(files)==432,'EXACT_PUBLIC_EXPORT_SET')
    for name in ('OUTPUT_MANIFEST.json','COMPLETED.json'):
        path=sink.root/name

        raw=read_exact(path,sink.final_identities[name]);bounded_public(raw);files[name]=raw
    review={'schema':'rtm-sensitivity-public-review-manifest/1.0','files':{n:identity(v) for n,v in files.items()},
        'private_payloads_included':False,'existing_input_payloads_included':False,
        'gate_d_e_accepted':False,'end_to_end_pass':False}
    files['REVIEW_MANIFEST.json']=canonical(review)
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,raw in files.items():archive.writestr(name,raw)
    raw=buffer.getvalue();path=sink.root/'S1_S4_DIAGNOSTICS_PUBLIC_REVIEW.zip'
    artifact=write_new(path,raw,private=False)
    return {'path':path,'artifact':artifact,'member_count':len(files),'private_members':0}
