from pathlib import Path
import re

from sensitivity_replay import public_bytes
from io_boundary import require,canonical,identity,plain,write_new,read_exact,strict_json

CELL_PRIVATE={'score_payload.json','actual_evaluation_private.json','permuted_evaluation_private.json'}
CELL_PUBLIC={'score_state.json','score_receipt.json','replay_receipt.json',
             'actual_evaluation_receipt.json','permuted_evaluation_receipt.json','tie_diagnostics.json'}


def output_contract():
    result={}
    for s in ('S1','S2','S3','S4'):
        for i in range(17):
            prefix=s+'/CFG%02d/'%i
            result.update({prefix+name:True for name in CELL_PRIVATE})
            result.update({prefix+name:False for name in CELL_PUBLIC})
        result[s+'/risk_audit_private.json']=True
        result[s+'/scenario_receipt.json']=False
    result.update({'diagnostics/CFG%02d.json'%i:False for i in range(17)})
    result.update({'matrix_receipt.json':False,'DIAGNOSTICS_RECEIPT.json':False,'CONTROLLER_RESULT.json':False})
    return result


def bounded_public(data):
    obj=strict_json(data);public_bytes(obj)
    forbidden={'target_rids','target_indices','canonical_rids','outlier_mask','is_outlier',
        'base_matrix','s4_matrix','cluster_multiplicities','canonical_cluster_order',
        'target_cluster_membership','source_rows','release_rows','rows','retained_canonical_rids'}
    def visit(value):
        if isinstance(value,dict):
            require(not forbidden.intersection(value),'PRIVATE_FIELD_IN_PUBLIC_OUTPUT')
            for v in value.values():visit(v)
        elif isinstance(value,list):
            for v in value:visit(v)
    visit(obj)
    return obj


class ProtectedSink:
    def __init__(self,output,policy):
        self.root=policy.new_directory(output,protected=True);self.policy=policy
        self.private=policy.new_directory(self.root/'private',protected=True)
        self.public=policy.new_directory(self.root/'public',protected=False)
        self.allowed=output_contract();self.entries={};self.closed=False;self.private_acl_receipt=None
        self.policy.inspect([self.root,self.private])

    def __call__(self,name,data,*,private):
        require(not self.closed,'SINK_ALREADY_FINISHED')
        require(name in self.allowed and self.allowed[name] is private,'OUTPUT_ROLE_OR_VISIBILITY_MISMATCH')
        require(name not in self.entries,'OUTPUT_ALREADY_COMMITTED')
        if not private: bounded_public(data)
        filename=name.replace('/','__')
        require(re.fullmatch(r'[A-Za-z0-9_.]+',filename) is not None,'OUTPUT_FILENAME_INVALID')
        path=(self.private if private else self.public)/filename
        result=write_new(path,data,private=private)
        record={'logical_name':name,'relative_path':path.relative_to(self.root).as_posix(),
                'visibility':'PRIVATE_DO_NOT_UPLOAD' if private else 'PUBLIC_AGGREGATES','artifact':result}

        checkpoint=self.root/('CHECKPOINT_%04d.json'%len(self.entries))
        write_new(checkpoint,canonical(record),private=True)
        self.entries[name]=record
        return result

    def read_new(self,name,*,audit=False):
        require(name in self.entries,'UNCOMMITTED_NEW_OUTPUT')
        entry=self.entries[name]
        if entry['visibility']=='PRIVATE_DO_NOT_UPLOAD':
            require(audit and name in {s+'/risk_audit_private.json' for s in ('S1','S2','S3','S4')},
                    'ONLY_NEW_SCENARIO_AUDITS_ALLOWED_FOR_NUMERIC_VERIFICATION')
        return read_exact(self.root/entry['relative_path'],entry['artifact'])

    def inspect_private_outputs(self):
        paths=[self.root,self.private]+[self.root/e['relative_path'] for e in self.entries.values()
                                      if e['visibility']=='PRIVATE_DO_NOT_UPLOAD']
        self.private_acl_receipt=self.policy.inspect(paths)
        return self.private_acl_receipt

    def finish(self):
        require(set(self.entries)==set(self.allowed),'CONTROLLER_OUTPUT_SET_INCOMPLETE')
        require(self.private_acl_receipt is not None,'PRIVATE_OUTPUT_ACL_POSTCHECK_REQUIRED')
        require(sum(e['visibility']=='PRIVATE_DO_NOT_UPLOAD' for e in self.entries.values())==208,
                'PRIVATE_OUTPUT_COUNT')
        manifest={'schema':'rtm-sensitivity-output-manifest/1.0','mode':self.policy.mode,
            'files':self.entries,'file_count':640,'private_count':208,'public_count':432,
            'private_outputs_hash_verified_after_write':True,'file_flush_before_acknowledgement':True,
            'private_acl_postcheck':self.private_acl_receipt,'automatic_retry_or_resume':False}
        raw=canonical(manifest);mid=write_new(self.root/'OUTPUT_MANIFEST.json',raw,private=True)
        marker={'schema':'rtm-sensitivity-controller-completion/1.0',
            'result':'COMPLETED_PENDING_INDEPENDENT_REVIEW' if self.policy.mode=='operational' else 'SYNTHETIC_COMPLETED',
            'mode':self.policy.mode,'output_manifest':mid,'controller_result':self.entries['CONTROLLER_RESULT.json']['artifact'],
            'gate_d_e_accepted':False,'end_to_end_pass':False,'existing_outputs_or_claims_modified':False}
        cid=write_new(self.root/'COMPLETED.json',canonical(marker),private=True)
        self.final_identities={'OUTPUT_MANIFEST.json':mid,'COMPLETED.json':cid};self.closed=True
        return marker
