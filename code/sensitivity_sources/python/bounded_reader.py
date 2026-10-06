import csv
import io
from pathlib import Path,PurePosixPath
from dataclasses import dataclass

import attack_adapter as adapter
from common import json_digest
from pinned_context import PINS
from reader_pins import EXTRA_PINS,INPUT_CONTRACT_IDENTITY
from sensitivity_runner import CFGS,PHYSICAL,parse_source_bytes,admit_inputs
from io_boundary import require,plain,snapshot,read_exact,strict_json,identity,canonical

_SEAL=object()


@dataclass(frozen=True,repr=False)
class ReadPermit:
    mode:str
    root:Path
    contract_digest:str
    _seal:object


def permit_for_validated_controller(mode,root,contract,*,authorization_validated):

    require(authorization_validated is True,'READ_PERMISSION_NOT_ADMITTED')
    require(mode in ('synthetic','operational'),'READER_MODE')
    return ReadPermit(mode,plain(root),json_digest(contract),_SEAL)


def load_public_inputs(package):
    root=Path(package)
    def get(relative,expected_digest=None):

        p=root/relative;require(p.stat().st_size<=1_000_000,'PUBLIC_EVIDENCE_SIZE')
        obj=strict_json(p.read_bytes())
        if expected_digest is not None:require(json_digest(obj)==expected_digest,'PUBLIC_RECEIPT_PIN_MISMATCH')
        return obj
    raw=(root/'DATA_INPUT_CONTRACT.json').read_bytes()
    require(identity(raw)==INPUT_CONTRACT_IDENTITY,'INPUT_ALLOWLIST_PIN_MISMATCH')
    contract=strict_json(raw)
    public={'target_receipt':get('evidence/target_sample_receipt.json',PINS['receipts']['target_sample_receipt.json']),
        'noise_receipt':get('evidence/noise_receipt.json',PINS['receipts']['noise_receipt.json']),
        'bootstrap_receipt':get('evidence/risk_bootstrap_receipt.json',PINS['receipts']['risk_bootstrap_receipt.json']),
        'configurations':{}}
    for cfg in CFGS:
        values={}
        for filename in ('score_state.json','score_receipt.json','permutation_receipt.json','actual_evaluation_receipt.json'):
            name='base/'+cfg+'/'+filename
            values[filename]=get('evidence/'+name,PINS['receipts'][name])
        name='evidence/cfg00_raw_control_receipt.json' if cfg=='CFG00' else 'evidence/gate_b/'+cfg+'.gate-b.json'
        values['release_receipt']=get(name,EXTRA_PINS[name])
        require(json_digest(values['release_receipt'])==values['permutation_receipt.json']['release_validation_receipt_json_sha256'],
                'PUBLIC_RELEASE_NOT_BOUND_TO_BASE')
        public['configurations'][cfg]=values
    return contract,public


class BoundedReader:
    def __init__(self,contract,permit,policy):
        require(type(permit) is ReadPermit and permit._seal is _SEAL
                and permit.contract_digest==json_digest(contract) and permit.mode==policy.mode,
                'READER_PERMIT_MISMATCH')
        require(type(contract) is dict and len(contract['bindings'])==80,'EXACT_80_INPUT_BINDINGS_REQUIRED')
        if permit.mode=='operational':
            require(identity(canonical(contract))['sha256']==identity(canonical(strict_json(
                (Path(__file__).resolve().parents[1]/'DATA_INPUT_CONTRACT.json').read_bytes())))['sha256'],
                'OPERATIONAL_INPUT_CONTRACT_CHANGED')
        self.permit=permit;self.policy=policy;self.entries={};self.reads={};self.before={};self.protected=[]
        for item in contract['bindings']:
            role=item['role'];require(role not in self.entries,'DUPLICATE_INPUT_ROLE')
            if item['path_scope']=='repository_relative':
                rel=PurePosixPath(item['path'])
                require(not rel.is_absolute() and '..' not in rel.parts and '\\' not in item['path']
                        and ':' not in item['path'],'INPUT_PATH_ESCAPE')
                path=permit.root.joinpath(*rel.parts)
            else:
                require(item['path_scope']=='absolute_windows_path' and permit.mode=='operational',
                        'EXTERNAL_INPUT_PATH_NOT_ADMITTED')
                path=Path(item['path'])
            path=plain(path)
            protected=(item.get('protected_private') is True or item['path_scope']=='absolute_windows_path'
                       or item['path'].startswith('private/'))
            self.entries[role]=(path,item['identity'],protected)
            state=snapshot(path);require(state[2]==item['identity']['bytes'],'ALLOWLIST_LENGTH_MISMATCH')
            self.before[role]=state;self.reads[role]=0
            if protected:self.protected.append(path)
        require(len({v[0] for v in self.entries.values()})==80,'DUPLICATE_INPUT_PATH')
        if permit.mode=='synthetic':
            require(sum(v[1]['bytes'] for v in self.entries.values())<=10_000_000,
                    'SYNTHETIC_FILE_BYTES_BOUNDARY')
        self.acl_before=policy.inspect(self.protected)

    def read(self,role):
        require(role in self.entries,'ROLE_OUTSIDE_ALLOWLIST')
        require(self.reads[role]==0,'EXISTING_INPUT_REREAD_FORBIDDEN')
        path,expected,_=self.entries[role]
        require(snapshot(path)==self.before[role],'INPUT_CHANGED_AFTER_ADMISSION')
        self.reads[role]+=1
        return read_exact(path,expected)

    def json(self,role):return strict_json(self.read(role))

    def finish(self):
        require(all(v==1 for v in self.reads.values()),'ALL_80_INPUTS_MUST_BE_READ_EXACTLY_ONCE')
        require(all(snapshot(self.entries[r][0])==s for r,s in self.before.items()),'INPUT_METADATA_CHANGED_DURING_EXECUTION')
        post=self.policy.inspect(self.protected)
        return {'result':'PASS','bound_input_count':80,'payload_reads':sum(self.reads.values()),
            'reads_per_input':1,'payload_rereads':0,'input_metadata_unchanged':True,
            'input_acl_before':self.acl_before,'input_acl_after':post,
            'input_contract_json_digest':self.permit.contract_digest,'existing_files_modified':False}


def table(data,delimiter,header=None):
    try:
        rows=list(csv.reader(io.StringIO(data.decode('utf-8-sig'),newline=''),delimiter=delimiter,strict=True))
    except (UnicodeError,csv.Error):raise ValueError('INPUT_TABLE_PARSE') from None
    require(rows and all(all(v and v==v.strip() and not any(c in v for c in ('\0','\r','\n','\t')) for v in row) for row in rows),
            'INPUT_TABLE_CELLS')
    if header is not None:
        require(tuple(rows[0])==tuple(header),'INPUT_TABLE_HEADER');rows=rows[1:]
        require(rows and all(len(r)==len(header) for r in rows),'INPUT_TABLE_RECTANGLE')
        return [dict(zip(header,r)) for r in rows]
    require(len({len(r) for r in rows})==1 and len(rows[0])>=2,'HIERARCHY_RECTANGLE')
    return {'levels':list(range(len(rows[0]))),'rows':rows}


def lines(data,*,integers=False):
    try: values=data.decode('ascii').splitlines()
    except UnicodeError:raise ValueError('INPUT_LINES_ENCODING') from None
    require(values and data==('\n'.join(values)+'\n').encode('ascii'),'CANONICAL_LF_LINES_REQUIRED')
    if integers:
        require(all(v.isascii() and v.isdecimal() and str(int(v))==v for v in values),'CANONICAL_INTEGER_LINES')
        return [int(v) for v in values]
    return values


def load_matrix_inputs(reader,public):
    from common import QIS
    common={'source_bytes':reader.read('training_table'),
        'canonical_rids':lines(reader.read('canonical_rids')),
        'master_permutation':lines(reader.read('master_permutation'),integers=True),
        'hierarchy_tables':{a:table(reader.read('hierarchy_'+a),';') for a in QIS},
        'target_private':reader.json('target_sample'),'target_receipt':public['target_receipt'],
        'noise_private':reader.json('noise_matrices'),'noise_receipt':public['noise_receipt'],
        'bootstrap_audit':reader.json('saved_BASE_bootstrap_audit'),'bootstrap_receipt':public['bootstrap_receipt']}
    source=parse_source_bytes(common['source_bytes']);configurations={}
    for cfg in CFGS:
        p=public['configurations'][cfg]
        if cfg=='CFG00': rows=source;flags=[False]*len(source);levels={a:0 for a in QIS};report_raw=None
        else:
            rows=table(reader.read('full_output_'+cfg),'\t',PHYSICAL)
            report_raw=reader.read('captured_java_report_'+cfg);report=strict_json(report_raw)
            flags=report['outlier_mask']['values'];levels=report['transformation_by_name']
        configurations[cfg]={'release_rows':rows,'is_outlier':flags,'transformation_by_name':levels,
            'release_receipt':p['release_receipt'],'producer_report_bytes':report_raw,
            'base_private':reader.json('saved_permutation_'+cfg),'base_receipt':p['permutation_receipt.json'],
            'base_state':p['score_state.json']}
    admitted=admit_inputs(common,configurations,fixture_mode=reader.permit.mode=='synthetic')
    return common,configurations,admitted
