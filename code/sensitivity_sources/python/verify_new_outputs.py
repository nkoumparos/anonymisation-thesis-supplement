from fractions import Fraction
from math import isfinite

from common import json_digest
from io_boundary import require,strict_json,identity
from sensitivity_runner import CFGS,PAIRS


def quantile(sample,numerator):
    ordered=sorted(sample)
    require(len(ordered)>=2 and all(type(v) in (int,float) and isfinite(v) for v in ordered),
            'VERIFIER_FINITE_REPLICATES')
    rank=Fraction((len(ordered)-1)*numerator,40);lo=rank.numerator//rank.denominator
    weight=float(rank-lo)
    return (1.0-weight)*ordered[lo]+weight*ordered[min(lo+1,len(ordered)-1)]


def close(a,b):return type(a) in (int,float) and type(b) in (int,float) and isfinite(a) and isfinite(b) and abs(a-b)<=1e-12


def verify_new_audits(sink,matrix,base_receipt):
    verified=0;artifacts={}
    require(matrix['cell_count']==68 and matrix['interval_count']==156,'VERIFIER_MATRIX_COUNTS')
    for scenario in ('S1','S2','S3','S4'):
        raw=sink.read_new(scenario+'/risk_audit_private.json',audit=True);audit=strict_json(raw)
        artifacts[scenario]=identity(raw)
        require(audit['schema']=='rtm-scenario-risk-private-audit/1.0' and audit['scenario']==scenario
                and audit['visibility']=='PRIVATE_DO_NOT_UPLOAD'
                and audit['base_audit_artifact']==base_receipt['private_audit'],'VERIFIER_AUDIT_BINDING')
        point=audit['point_consumer'];negative=audit['permuted_point_consumer'];bootstrap=audit['bootstrap_consumer']
        for consumer in (point,negative,bootstrap):
            require(consumer['aggregate_validation_status']=='PASS'
                    and consumer['payload']['guard_receipt']['status']=='PASS'
                    and consumer['output_payload_json_sha256']==json_digest(consumer['payload']),
                    'VERIFIER_GUARD_PAYLOAD_BINDING')
        guard=bootstrap['payload']['guard_receipt']
        require(guard['cluster_order_sha256']==base_receipt['cluster_order_sha256']
                and guard['cluster_multiplicities_sha256']==base_receipt['cluster_multiplicities_sha256']
                and guard['replicate_count']==base_receipt['replicates'],'VERIFIER_BASE_PLAN_BINDING')
        public=matrix['scenarios'][scenario];points=point['payload']['aggregates'];reports=bootstrap['payload']['aggregates']
        require(public['point_risk']==points and public['permuted_point_risk']==negative['payload']['aggregates'],
                'VERIFIER_PUBLISHED_POINT_VALUES')
        require(set(reports)==set(CFGS),'VERIFIER_CFG_COMPLETENESS')
        samples={c:[r['R_all'] for r in reports[c]['replicates']] for c in CFGS}
        specifications=[('R_all',c,c,None) for c in CFGS]
        specifications += [('difference_vs_raw',c,c,'CFG00') for c in CFGS[1:]]
        specifications += [('suppression_differences',s+'_minus_'+n,s,n) for n,s in PAIRS]
        require(sum(len(v) for v in public['intervals'].values())==39,'VERIFIER_INTERVAL_FAMILIES')
        for family,key,positive,negative_cfg in specifications:
            sample=samples[positive] if negative_cfg is None else [a-b for a,b in zip(samples[positive],samples[negative_cfg])]
            require(len(sample)==base_receipt['replicates'],'VERIFIER_REPLICATE_COUNT')
            estimate=points[positive]['R_all']-(0 if negative_cfg is None else points[negative_cfg]['R_all'])
            entry=public['intervals'][family][key]
            require(close(entry['point_estimate'],estimate) and len(entry['stability_interval_95'])==2
                    and all(close(a,b) for a,b in zip(entry['stability_interval_95'],[quantile(sample,1),quantile(sample,39)])),
                    'VERIFIER_INTERVAL_ENDPOINT_MISMATCH')
            verified+=1
        for c in CFGS:
            require(public['zero_retained_replicates'][c]==sum(r['N_ret']==0 for r in reports[c]['replicates']),
                    'VERIFIER_ZERO_RETAINED_COUNTS')
    require(verified==156,'VERIFIER_TOTAL_INTERVALS')
    return {'result':'PASS_WITHIN_NEW_AUDIT_VERIFICATION_SCOPE','intervals_independently_recomputed':verified,
            'new_private_audits_read':4,'audit_artifacts':artifacts,'endpoint_tolerance':1e-12,
            'original_input_payloads_reread':False,'new_rng_generation':False,'gate_d_e_accepted':False,'end_to_end_pass':False}
