from collections import Counter
from dataclasses import dataclass
from math import fsum, isfinite
import hashlib
import json

import permutation_control as legacy
import attack_adapter as adapter
from common import exact_keys, integer, json_digest, require
from attack_scorer import scenario_attributes, scenario_pmf
from diagnostic_core import tie_diagnostics

SCENARIOS=('S1','S2','S3','S4')
REPLAY_SCHEMA='rtm-scenario-permutation-replay/1.0'
EVALUATION_SCHEMA='rtm-sensitivity-evaluation-public/1.0'
PRIVATE_EVALUATION_SCHEMA='rtm-sensitivity-evaluation-private/1.0'
_SEAL=object()


def canonical(value):
    return (json.dumps(value,ensure_ascii=True,allow_nan=False,sort_keys=True,
                       separators=(',',':'))+'\n').encode('ascii')


def identity(data):
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def line_hash(values):
    return hashlib.sha256(('\n'.join(str(v) for v in values)+'\n').encode('utf-8')).hexdigest()


def public_bytes(value):
    data=canonical(value)
    forbidden=(b'adult.data:',b'"success_draws"',b'"target_ids"',b'"release_ids"',
               b'"actual_row_to_rid"',b'"permuted_row_to_rid"',b'"sigma_c"',
               b'"winner_group_ids"',b'"target_position"',b'"records"')
    require(not any(word in data for word in forbidden),'SENS_PUBLIC_LEAK',
            'Only bounded aggregates and commitments can be public')
    return data


@dataclass(frozen=True,repr=False)
class Replay:

    actual: tuple
    permuted: tuple
    receipt_bytes: bytes
    score_state_digest: str
    mapping_digest: str
    fixture_mode: bool
    _seal: object


def _new_score(bundle, fixture_mode):
    exact_keys(bundle,{'score_payload','score_state','bounded_receipt'},'score bundle')
    payload,state,receipt=(bundle[k] for k in ('score_payload','score_state','bounded_receipt'))
    adapter._validate_score_bundle(payload,state,receipt)
    require(state['scenario'] in SCENARIOS,'SENS_SCENARIO','S1-S4 score state required')
    require(receipt.get('scope')==('SYNTHETIC_FIXTURE' if fixture_mode else 'OPERATIONAL_CFG_SCENARIO'),
            'SENS_SCORE_SCOPE','Score scope differs from admitted mode')
    require(receipt.get('scenario_attributes')==list(scenario_attributes(state['scenario']))
            and receipt.get('scenario_pmf')==[[a,b] for a,b in scenario_pmf(state['scenario'])],
            'SENS_MATCHED_Q','Score receipt does not use the frozen scenario K/q')
    return payload,state,receipt


def rebind_existing_permutation(*,canonical_rids,master_permutation,is_outlier,
                               release_receipt,base_private,base_receipt,base_state,
                               score_bundle,fixture_mode=False):

    require(type(fixture_mode) is bool,'SENS_MODE','Mode must be explicit Boolean')
    payload,state,score_receipt=_new_score(score_bundle,fixture_mode)
    cfg=state['config_id']
    rids,master,flags=legacy._population(canonical_rids,master_permutation,is_outlier,fixture_mode)
    if fixture_mode:
        require(len(rids)<=64 and state['target_count']<=32 and state['draw_count']<=30,
                'SENS_FIXTURE_BOUNDARY','Synthetic replay is restricted to small constructed fixtures')
    n=sum(not f for f in flags)
    release_binding=legacy._release_gate(release_receipt,cfg,len(rids),n,fixture_mode)
    legacy._score_state(base_state,cfg,n,fixture_mode)
    old_receipt_bytes=legacy.bounded_receipt_bytes(base_receipt)
    old_private_bytes=legacy.private_record_bytes(base_private)
    require(base_receipt.get('result')=='PASS' and base_receipt.get('config_id')==cfg
            and base_receipt.get('permutation_subgate')=='PASS'
            and base_receipt.get('scope')==('SYNTHETIC_FIXTURE' if fixture_mode else 'OPERATIONAL_CFG'),
            'SENS_BASE_RECEIPT','A matching previously accepted BASE receipt is required')
    require(base_receipt.get('private_record_json')==identity(old_private_bytes),
            'SENS_OLD_PRIVATE_HASH','Archived permutation bytes differ from the original commitment')
    require(base_private.get('config_id')==cfg and base_private.get('effective_protocol')=='v1.2.4'
            and base_private.get('visibility')=='PRIVATE_DO_NOT_STAGE_OR_PUBLISH',
            'SENS_OLD_PRIVATE_SCOPE','Archived private record scope differs')
    require(base_receipt.get('score_state_json_sha256')==json_digest(base_state)
            ==base_private.get('score_state_sha256_before_assignment')
            and base_receipt.get('score_payload_sha256')==base_state['score_payload_sha256'],
            'SENS_BASE_SCORE_BINDING','Archived mapping is not bound to the admitted BASE state')
    for k in ('candidate_order_sha256','target_order_sha256','candidate_row_count','target_count','draw_count','score_record_count'):
        require(base_state[k]==state[k],'SENS_REPLAY_POPULATION','Scenario changed the frozen row or target order/count')
    require(base_receipt.get('candidate_order_sha256')==state['candidate_order_sha256']
            and base_receipt.get('target_order_sha256')==state['target_order_sha256']
            and score_receipt.get('candidate_order_sha256')==state['candidate_order_sha256']
            and score_receipt.get('target_order_sha256')==state['target_order_sha256'],
            'SENS_ORDER_BINDINGS','Public order commitments differ')
    require(base_receipt.get('release_validation_receipt_json_sha256')==json_digest(release_receipt)
            ==score_receipt.get('release_validation_receipt_sha256')
            and base_receipt.get('release_output_sha256')==release_binding['release_output_sha256']
            and base_receipt.get('producer_report_sha256')==release_binding['producer_report_sha256'],
            'SENS_RELEASE_BINDING','Release validation is not the archived release')
    pub=[i for i in master if not flags[i]]
    retained=[r for r,f in zip(rids,flags) if not f]
    actual=[rids[i] for i in pub]
    sigma=base_private.get('sigma_c')
    require(type(sigma) is list and len(sigma)==n
            and all(type(v) is int for v in sigma) and sorted(sigma)==list(range(n)),
            'SENS_SIGMA_BIJECTION','Existing sigma_c must be a complete index bijection')
    permuted=[retained[i] for i in sigma]
    for k,v in {'published_source_indices':pub,'retained_canonical_rids':retained,
                'actual_row_to_rid':actual,'permuted_row_to_rid':permuted,
                'canonical_rid_count':len(rids),'retained_count':n,
                'cfg_numeric_id':int(cfg[3:])}.items():
        require(base_private.get(k)==v,'SENS_ARCHIVED_MAPPING','Archived mapping differs from canonical order/Pi/mask')
    shared={'canonical_rid_order_sha256':line_hash(rids),'master_permutation_sha256':line_hash(master),
            'outlier_mask_sha256':line_hash([int(f) for f in flags]),
            'sigma_index_fixed_point_count':sum(i==v for i,v in enumerate(sigma)),
            'unchanged_row_to_rid_association_count':sum(a==b for a,b in zip(actual,permuted))}
    for k,v in shared.items():
        require(base_private.get(k)==v==base_receipt.get(k),'SENS_MAPPING_COUNTS','Archived mapping hash/count differs')
    require(base_receipt.get('n_input')==len(rids) and base_receipt.get('n_c')==n
            and base_receipt.get('outlier_count')==sum(flags)
            and base_receipt.get('sigma_c_sha256')==line_hash(sigma)
            and base_receipt.get('full_mapping_tsv')==identity(legacy._mapping_bytes(base_private)),
            'SENS_MAPPING_ARTIFACT','Full archived permutation evidence differs')
    seed=base_private.get('seed_derivation',{})
    require(seed.get('seed_sequence_entropy')==[11007,int(cfg[3:])]
            and seed.get('master_seed_11002_instantiated') is False
            and base_receipt.get('seed_sequence_entropy')==[11007,int(cfg[3:])]
            and base_receipt.get('master_rng_instantiated_or_reused') is False,
            'SENS_SEED_LINEAGE','Existing sigma uses the wrong seed lineage')
    assertions=base_receipt.get('structural_assertions')
    needed={'sigma_reproducible','sigma_bijection','actual_mapping_bijection','permuted_mapping_bijection',
            'published_order_is_pi_restricted_to_boolean_retained_mask','scores_complete_before_assignment',
            'separate_seedsequence_from_11002','full_private_logging_bound_by_hash'}
    require(type(assertions) is dict and needed<=set(assertions)
            and all(assertions[k]=='PASS' for k in needed),
            'SENS_OLD_STRUCTURAL_EVIDENCE','Required prior structural assertions are absent')
    if not fixture_mode:
        require(seed.get('numpy_version')=='2.0.2' and base_receipt.get('fresh_sigma_generation_count')==2,
                'SENS_ORIGINAL_REPRODUCTION','Original native reproducibility evidence differs')
    mapping_digest=json_digest({'actual':actual,'permuted':permuted})
    receipt={'schema':REPLAY_SCHEMA,'effective_protocol':'v1.2.4','result':'PASS_WITHIN_REPLAY_SCOPE',
             'scope':'SYNTHETIC_FIXTURE' if fixture_mode else 'SUPPLIED_OPERATIONAL_ARTIFACTS',
             'config_id':cfg,'scenario':state['scenario'],'candidate_row_count':n,
             'base_receipt_json_digest':json_digest(base_receipt),
             'base_receipt_artifact':identity(old_receipt_bytes),'base_private_artifact':identity(old_private_bytes),
             'base_score_state_json_digest':json_digest(base_state),'new_score_state_json_digest':json_digest(state),
             'new_score_payload_sha256':state['score_payload_sha256'],
             'candidate_order_sha256':state['candidate_order_sha256'],'target_order_sha256':state['target_order_sha256'],
             'mapping_pair_json_digest':mapping_digest,'existing_sigma_sha256':line_hash(sigma),
             'original_reproducibility_evidence_preserved':True,'new_rng_generation':False,
             'old_receipts_modified':False,'scores_complete_before_replay':True,
             'private_values_in_receipt':False,'execution_authorization_conferred':False,**shared}
    require(legacy.private_record_bytes(base_private)==old_private_bytes
            and legacy.bounded_receipt_bytes(base_receipt)==old_receipt_bytes,
            'SENS_OLD_ARTIFACT_MUTATION','Historical artifacts changed during replay')
    return Replay(tuple(actual),tuple(permuted),public_bytes(receipt),json_digest(state),
                  mapping_digest,fixture_mode,_SEAL)


def evaluate_with_replay(*,score_bundle,replay,canonical_rids,source_rows,
                         target_private,target_receipt,mapping_role):
    require(type(replay) is Replay and replay._seal is _SEAL,'SENS_REPLAY_ADMISSION','Validated replay required')
    require(mapping_role in ('ACTUAL','PERMUTED'),'SENS_MAPPING_ROLE','ACTUAL or PERMUTED required')
    payload,state,_=_new_score(score_bundle,replay.fixture_mode)
    require(json_digest(state)==replay.score_state_digest
            and json_digest({'actual':list(replay.actual),'permuted':list(replay.permuted)})==replay.mapping_digest,
            'SENS_REPLAY_CHANGED','Admitted score state or private mappings changed')
    rids,source=adapter._population(canonical_rids,source_rows,replay.fixture_mode)
    indices,targets,target_hash=adapter._targets(target_private,target_receipt,rids,replay.fixture_mode)
    require(target_hash==state['target_order_sha256'],'SENS_TARGET_REPLAY','Evaluator target order differs')
    mapping=replay.actual if mapping_role=='ACTUAL' else replay.permuted
    n=integer(payload['candidate_row_count'],'candidate count',1)
    groups=payload['candidate_group_sizes'];by_position=payload['candidate_group_id_by_position']
    require(type(groups) is list and groups and all(type(x) is int and x>0 for x in groups)
            and len(groups)==payload['candidate_group_count'] and sum(groups)==n
            and len(mapping)==len(by_position)==n
            and all(type(x) is int and 0<=x<len(groups) for x in by_position),
            'SENS_GROUP_SHAPE','Candidate grouping is invalid')
    counts=Counter(by_position)
    require([counts[i] for i in range(len(groups))]==groups,'SENS_GROUP_COUNTS','Group sizes do not preserve duplicates')
    records=payload['records'];draw_count=integer(payload['draw_count'],'draw count',1)
    require(len(records)==len(targets)*draw_count==payload['score_record_count'],
            'SENS_RECORD_COUNT','Expected a complete target-major/draw-minor matrix')
    positions={rid:i for i,rid in enumerate(mapping)}
    success=[[] for _ in targets];attempts=0;true_in_best=0
    threshold_counts={m:0 for m in (1,2,5,10)};threshold_success={m:[] for m in threshold_counts}
    tie_records=[]
    for offset,record in enumerate(records):
        exact_keys(record,{'target_position','draw_index','maximum_score_float_hex','winner_group_ids','tie_size','attempted'},'score record')
        i,r=divmod(offset,draw_count)
        require(type(record['target_position']) is int and type(record['draw_index']) is int
                and record['target_position']==i and record['draw_index']==r,
                'SENS_RECORD_ORDER','Score records are not in canonical target/draw order')
        winners=record['winner_group_ids']
        require(type(winners) is list and all(type(x) is int and 0<=x<len(groups) for x in winners)
                and len(set(winners))==len(winners),'SENS_WINNER_GROUPS','Invalid winning groups')
        size=integer(record['tie_size'],'tie size')
        require(size==sum(groups[x] for x in winners) and type(record['attempted']) is bool
                and record['attempted']==bool(winners),'SENS_TIE_DENOMINATOR','Tie size differs from winning row multiplicities')
        try:
            maximum=float.fromhex(record['maximum_score_float_hex'])
        except (ValueError,TypeError,OverflowError):
            raise ValueError('SENS_MAXIMUM_SCORE') from None
        require(isfinite(maximum) and 0<=maximum<=1 and (maximum>0)==bool(winners),
                'SENS_ABSTENTION','Score maximum and abstention disagree')
        position=positions.get(targets[i]);hit=position is not None and by_position[position] in winners
        value=1.0/size if hit else 0.0
        success[i].append(value);attempts+=bool(winners);true_in_best+=hit
        tie_records.append({'tie_size':size,'attempted':bool(winners)})
        for m in threshold_counts:
            if 1<=size<=m:
                threshold_counts[m]+=1;threshold_success[m].append(value)
    means=[fsum(x)/len(x) for x in success];retained=sum(r in positions for r in targets)
    total=fsum(means);pair_count=len(records)
    private={'schema':PRIVATE_EVALUATION_SCHEMA,'visibility':'PRIVATE_DO_NOT_PUBLISH',
             'config_id':state['config_id'],'scenario':state['scenario'],'mapping_role':mapping_role,
             'target_ids':targets,'release_ids':list(mapping),'success_draws':success,
             'cluster_keys':[[source[i][a] for a in ('age','sex','education','marital-status')] for i in indices]}
    private_data=canonical(private)
    receipt={'schema':EVALUATION_SCHEMA,'effective_protocol':'v1.2.4','result':'PASS_WITHIN_EVALUATION_SCOPE',
             'scope':'SYNTHETIC_FIXTURE' if replay.fixture_mode else 'SUPPLIED_OPERATIONAL_ARTIFACTS',
             'config_id':state['config_id'],'scenario':state['scenario'],'mapping_role':mapping_role,
             'candidate_row_count':n,'target_count':len(targets),'draw_count':draw_count,'pair_count':pair_count,
             'retained_target_count':retained,'risk_all_estimate':total/len(targets),
             'risk_released_estimate':total/retained if retained else None,
             'execution_anomaly':retained==0,'attempt_count':attempts,'abstention_count':pair_count-attempts,
             'abstention_rate':(pair_count-attempts)/pair_count,'true_row_in_best_count':true_in_best,
             'true_row_in_best_rate':true_in_best/pair_count,
             'coverage_by_maximum_tie_size':{str(m):{'attempt_count':threshold_counts[m],
                 'coverage':threshold_counts[m]/pair_count,
                 'conditional_success':fsum(threshold_success[m])/threshold_counts[m] if threshold_counts[m] else None} for m in threshold_counts},
             'tie_summary':tie_diagnostics(tie_records,convention='type7_unweighted_items'),
             'score_payload_sha256_before_join':state['score_payload_sha256'],
             'score_payload_sha256_after_join':identity(adapter._score_payload_bytes(payload))['sha256'],
             'replay_receipt_artifact':identity(replay.receipt_bytes),'private_evaluation_artifact':identity(private_data),
             'numeric_risk_pass_fail_criterion':None,'execution_authorization_conferred':False,
             'private_values_in_receipt':False}
    require(receipt['score_payload_sha256_before_join']==receipt['score_payload_sha256_after_join'],
            'SENS_SCORE_MUTATION','Scoring payload changed during evaluation')
    return {'private_record':private,'public_receipt':receipt,
            'private_bytes':private_data,'public_bytes':public_bytes(receipt)}
