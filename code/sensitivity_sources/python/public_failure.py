import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile

ROOT=Path(__file__).resolve().parents[1]
_CODES=None
_COMPARISONS={'path_vs_open_handle','handle_stable_during_read','path_stable_during_read'}
_FIELDS={'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink','file_type'}


def _literal_codes():
    global _CODES
    if _CODES is None:
        _CODES=set()

        for folder in (ROOT/'python',ROOT/'frozen_python',ROOT/'tests'):
            for path in folder.glob('*.py'):
                for n in ast.walk(ast.parse(path.read_bytes(),filename=path.name)):
                    if isinstance(n,ast.Constant) and type(n.value) is str and re.fullmatch('[A-Z][A-Z0-9_]{1,95}',n.value):
                        _CODES.add(n.value)
    return _CODES


def _safe_metadata(value):
    if type(value) is not dict:return None
    result={'raw_metadata_values_or_file_paths_included':False}
    for group in _COMPARISONS:
        item=value.get(group)
        if item is None:result[group]=None
        elif type(item) is dict and set(item).issubset(_FIELDS) and all(type(v) is bool for v in item.values()):
            result[group]=dict(item)
    return result


def exception_evidence(error):
    codes=_literal_codes();chain=[];seen=set()
    while error is not None and id(error) not in seen and len(chain)<4:
        seen.add(id(error));kind=type(error).__name__
        item={'exception_type':kind if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',kind) else 'UNLISTED_TYPE'}
        code=getattr(error,'code',None)
        if type(code) is str and code in codes:item['source_literal_code']=code
        elif len(error.args)==1 and type(error.args[0]) is str and error.args[0] in codes:
            item['source_literal_code']=error.args[0]
        metadata=_safe_metadata(getattr(error,'metadata_checks',None))
        if metadata is not None:item['metadata_checks']=metadata
        for name in ('errno','winerror'):
            value=getattr(error,name,None)
            if type(value) is int and abs(value)<100000:item[name]=value
        frames=[];tb=error.__traceback__
        while tb is not None and len(frames)<20:
            path=Path(tb.tb_frame.f_code.co_filename)
            label=path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else 'external/'+path.name
            func=tb.tb_frame.f_code.co_name
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}|<module>',func):func='unnamed_frame'
            frames.append({'source':label,'function':func,'line':tb.tb_lineno});tb=tb.tb_next
        item['frames']=frames;chain.append(item);error=error.__cause__ or error.__context__
    return {'exception_chain':chain,'raw_messages_or_locals_included':False}


def _create_public(path,data):

    from io_boundary import plain,require
    p=plain(path);require(type(data) is bytes and 0<len(data)<=500000,'PUBLIC_PREFLIGHT_OUTPUT_BOUND')
    with p.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    state=p.lstat();require(stat.S_ISREG(state.st_mode) and state.st_nlink==1,'PUBLIC_PREFLIGHT_REGULAR_FILE')
    with p.open('rb') as stream:observed=stream.read(len(data)+1)
    require(observed==data,'PUBLIC_PREFLIGHT_OUTPUT_HASH_READBACK')


def publish_preflight(out,files):
    from io_boundary import canonical,identity,require
    from protected_sink import bounded_public
    allowed={'SYNTHETIC_VALIDATION.json','FILE_CONTROLLER_PROOF.json','PREFLIGHT_RECEIPT.json','REVIEW_MANIFEST.json'}
    require(set(files).issubset(allowed) and 'PREFLIGHT_RECEIPT.json' in files and 'REVIEW_MANIFEST.json' not in files,
            'PUBLIC_PREFLIGHT_FILE_SET')
    for data in files.values():bounded_public(data)
    files=dict(files)
    files['REVIEW_MANIFEST.json']=canonical({'schema':'rtm-reader-controller-preflight-review/1.0',
        'files':{n:identity(v) for n,v in files.items()},'actual_private_payloads_included':False,
        'constructed_private_fixture_files_included':False})
    for name,data in files.items():_create_public(out/name,data)
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in files.items():archive.writestr(name,data)
    path=out/'READER_CONTROLLER_PREFLIGHT_REVIEW.zip';_create_public(path,buffer.getvalue())
    return path
