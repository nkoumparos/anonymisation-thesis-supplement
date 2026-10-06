import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import risk_windows_acl as ACL


class BoundaryError(ValueError):
    def __init__(self,code):
        self.code=code;self.metadata_checks=None;super().__init__(code)


def require(ok,code):
    if not ok: raise BoundaryError(code)


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')


def identity(data): return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def strict_json(data):
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result,'DUPLICATE_JSON_KEY');result[k]=v
        return result
    def invalid(_): raise BoundaryError('NONFINITE_JSON')
    try: return json.loads(data,object_pairs_hook=pairs,parse_constant=invalid)
    except BoundaryError: raise
    except (ValueError,UnicodeError,RecursionError): raise BoundaryError('INVALID_JSON') from None


def plain(path):
    p=Path(path)
    require(p.is_absolute() and '..' not in p.parts,'ABSOLUTE_PLAIN_PATH_REQUIRED')
    for x in (p,*p.parents):
        if x.exists() or x.is_symlink():
            s=x.lstat()
            require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,
                    'REPARSE_OR_SYMLINK_PATH')
    return p


def snapshot(path):
    p=plain(path);s=p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'SINGLE_REGULAR_FILE_REQUIRED')
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


METADATA_POLICY='same_accessor_stability_with_exact_identity_size_and_sha256'
_STAT_FIELDS=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
_READ_METRICS={}


def reset_read_metrics():
    _READ_METRICS.clear()
    _READ_METRICS.update(read_calls=0,verified_reads=0,
        stable_cross_accessor_time_difference_reads=0,st_mtime_ns_differences=0,st_ctime_ns_differences=0)


def read_metrics():return {'metadata_policy':METADATA_POLICY,**_READ_METRICS}


reset_read_metrics()


def _handle_state(s):
    return tuple(getattr(s,k) for k in _STAT_FIELDS)+(s.st_nlink,stat.S_IFMT(s.st_mode))


def _metadata_evidence(path_before,handle_before,handle_after,path_after):
    def same(a,b,names):
        return None if a is None or b is None else {k:a[i]==b[i] for i,k in enumerate(names)}
    return {'path_vs_open_handle':same(path_before,handle_before,_STAT_FIELDS),
        'handle_stable_during_read':same(handle_before,handle_after,_STAT_FIELDS+('st_nlink','file_type')),
        'path_stable_during_read':same(path_before,path_after,_STAT_FIELDS),
        'raw_metadata_values_or_file_paths_included':False}


def read_exact(path,expected):

    require(type(expected) is dict and set(expected)=={'bytes','sha256'}
            and type(expected['bytes']) is int and 0<expected['bytes']<=150_000_000
            and type(expected['sha256']) is str and len(expected['sha256'])==64,
            'INVALID_FILE_COMMITMENT')
    before=opened_state=after_state=final_path=None
    _READ_METRICS['read_calls']+=1
    try:
        before=snapshot(path)
        require(before[2]==expected['bytes'],'INPUT_LENGTH_MISMATCH')
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as stream:
            opened=os.fstat(stream.fileno())
            opened_state=_handle_state(opened)
            require(opened_state[:3]==before[:3] and opened.st_nlink==1
                    and stat.S_ISREG(opened.st_mode),'OPENED_FILE_CHANGED')
            raw=stream.read(expected['bytes']+1)
            after=os.fstat(stream.fileno())
            after_state=_handle_state(after)
            require(after_state==opened_state,'FILE_CHANGED_WHILE_READING')
        final_path=snapshot(path)
        require(final_path==before,'FILE_REPLACED_WHILE_READING')
        require(identity(raw)==expected,'INPUT_HASH_MISMATCH')
        differences=[i for i in (3,4) if before[i]!=opened_state[i]]
        if differences:
            _READ_METRICS['stable_cross_accessor_time_difference_reads']+=1
            for i in differences:_READ_METRICS[_STAT_FIELDS[i]+'_differences']+=1
        _READ_METRICS['verified_reads']+=1
        return raw
    except BoundaryError as error:
        error.metadata_checks=_metadata_evidence(before,opened_state,after_state,final_path)
        raise
    except OSError:
        error=BoundaryError('BOUND_FILE_UNAVAILABLE')
        error.metadata_checks=_metadata_evidence(before,opened_state,after_state,final_path)
        raise error from None


def write_new(path,data,*,private=False):

    require(type(data) is bytes and data,'OUTPUT_BYTES_REQUIRED')
    p=plain(path);require(p.parent.is_dir(),'OUTPUT_PARENT_REQUIRED')
    try:
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(p,flags,0o600 if private else 0o644)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        require(read_exact(p,identity(data))==data,'NEW_OUTPUT_READBACK_MISMATCH')
        if sys.platform!='win32':
            parent_fd=os.open(p.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
        return identity(data)
    except BoundaryError: raise
    except FileExistsError: raise BoundaryError('OUTPUT_ALREADY_EXISTS') from None
    except OSError: raise BoundaryError('OUTPUT_WRITE_FAILED_PRESERVE_PARTIAL_FILE') from None


class FilePolicy:

    def __init__(self,mode):
        require(mode in ('synthetic','operational'),'EXPLICIT_IO_MODE_REQUIRED')
        require(mode=='synthetic' or sys.platform=='win32','OPERATIONAL_NATIVE_WINDOWS_REQUIRED')
        self.mode=mode;self.created=set();self.user_sid_sha256=None
        self.protected_directories=0;self.inspected_paths=0;self.native_calls=0

    def _native_receipt(self,result):
        sid=hashlib.sha256(result['current_user_sid'].encode('ascii')).hexdigest()
        require(self.user_sid_sha256 in (None,sid),'ACL_USER_CHANGED')
        self.user_sid_sha256=sid;self.native_calls+=1
        return identity(canonical(result))

    def new_directory(self,path,*,protected=True):
        p=plain(path);require(p.parent.is_dir(),'FRESH_DIRECTORY_PARENT_REQUIRED')
        require(not p.exists(),'DIRECTORY_ALREADY_EXISTS')
        p.mkdir(mode=0o700,exist_ok=False);self.created.add(p)
        if protected:
            require(p in self.created and not any(p.iterdir()),'ONLY_OWN_NEW_EMPTY_DIRECTORY_CAN_BE_PROTECTED')
            if sys.platform=='win32': self._native_receipt(ACL.protect_new_directory(str(p)))
            else:
                require(self.mode=='synthetic','NATIVE_ACL_REQUIRED');os.chmod(p,0o700)
                require(stat.S_IMODE(p.stat().st_mode)==0o700,'SYNTHETIC_DIRECTORY_MODE')
            self.protected_directories+=1
        return p

    def inspect(self,paths):
        values=[plain(p) for p in paths]
        require(len(set(values))==len(values),'DUPLICATE_ACL_PATH')
        summaries=[]
        for start in range(0,len(values),16):
            batch=values[start:start+16]
            if sys.platform=='win32': summaries.append(self._native_receipt(ACL.inspect_private_paths([str(p) for p in batch])))
            else:
                require(self.mode=='synthetic','NATIVE_ACL_REQUIRED')
                for p in batch:
                    s=p.stat();expected=0o700 if p.is_dir() else 0o600
                    require(stat.S_IMODE(s.st_mode)==expected and s.st_uid==os.getuid(),'SYNTHETIC_PRIVATE_MODE')
            self.inspected_paths+=len(batch)
        return {'scope':'NATIVE_WINDOWS' if sys.platform=='win32' else 'SYNTHETIC_POSIX',
                'path_count':len(values),'batch_receipt_identities':summaries,'user_sid_sha256':self.user_sid_sha256}

    def summary(self):
        return {'mode':self.mode,'native_windows_acl_used':sys.platform=='win32',
            'user_sid_sha256':self.user_sid_sha256,'new_directories_protected':self.protected_directories,
            'paths_inspected':self.inspected_paths,'native_acl_calls':self.native_calls,'existing_acls_modified':False}
