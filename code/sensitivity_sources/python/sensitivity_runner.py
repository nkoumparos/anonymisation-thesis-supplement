import csv
import io
import json
from math import isfinite

import attack_adapter as adapter
import risk_consumer as risk
import permutation_control as legacy
from common import QIS, exact_keys, json_digest, require
from pinned_context import PINS
from sensitivity_replay import (SCENARIOS, canonical, identity, public_bytes,
                                rebind_existing_permutation, evaluate_with_replay)

CFGS=tuple('CFG%02d'%i for i in range(17))
PAIRS=(('CFG02','CFG11'),('CFG03','CFG12'),('CFG05','CFG13'),
       ('CFG06','CFG14'),('CFG08','CFG15'),('CFG10','CFG16'))
BASE_K=('age','sex','education','marital-status')
PHYSICAL=('sex','age','race','marital-status','education','native-country',
          'workclass','occupation','salary-class')
COMMON_KEYS={'canonical_rids','source_bytes','master_permutation','hierarchy_tables',
             'target_private','target_receipt','noise_private','noise_receipt',
             'bootstrap_audit','bootstrap_receipt'}
CFG_KEYS={'release_rows','is_outlier','transformation_by_name','release_receipt',
          'producer_report_bytes','base_private','base_receipt','base_state'}


def parse_source_bytes(data):
    require(type(data) is bytes and data and b'\0' not in data,
            'SENS_SOURCE_BYTES','Exact source-table bytes required')
    try:
        rows=list(csv.reader(io.StringIO(data.decode('utf-8-sig'),newline=''),
                             delimiter=';',strict=True))
    except (UnicodeError,csv.Error):
        raise ValueError('SENS_SOURCE_PARSE') from None
    require(rows and tuple(rows[0])==PHYSICAL and len(rows)>1,
            'SENS_SOURCE_HEADER','Source table header differs')
    require(all(len(r)==len(PHYSICAL) and all(v and v==v.strip()
                and not any(c in v for c in ('\0','\r','\n','\t')) for v in r) for r in rows[1:]),
            'SENS_SOURCE_CELLS','Source table is nonrectangular or has invalid cells')
    return [dict(zip(PHYSICAL,r)) for r in rows[1:]]


def _pin(value,name,fixture_mode):
    if not fixture_mode:
        require(json_digest(value)==PINS['receipts'][name],
                'SENS_PINNED_PUBLIC_RECORD','Public record differs from accepted BASE evidence: '+name)


def existing_plan(common,source,fixture_mode):

    audit=common['bootstrap_audit'];receipt=common['bootstrap_receipt']
    _pin(receipt,'risk_bootstrap_receipt.json',fixture_mode)
    indices,targets,_=adapter._targets(common['target_private'],common['target_receipt'],
                                      common['canonical_rids'],fixture_mode)
    keys=[[source[i][a] for a in BASE_K] for i in indices]
    require(audit.get('schema')=='rtm-base-risk-bootstrap-private-audit/1.0'
            and audit.get('mode')==('synthetic' if fixture_mode else 'operational')
            and audit.get('visibility')=='PRIVATE_DO_NOT_UPLOAD'
            and receipt.get('schema')=='rtm-base-risk-bootstrap-public/1.0'
            and receipt.get('result')=='PASS'
            and receipt.get('mode')==audit['mode']
            and receipt.get('private_audit')==identity(canonical(audit))
            and audit.get('public_input_binding')==receipt.get('public_input_binding'),
            'SENS_ARCHIVED_PLAN_ARTIFACT','Saved BASE audit is not the committed artifact')
    order,membership,plan=risk._record_weights(keys,len(targets),audit.get('cluster_multiplicities'))
    require(audit.get('canonical_cluster_order')==order
            and audit.get('target_cluster_membership')==membership
            and receipt.get('cluster_order_sha256')==json_digest(order)
            and receipt.get('cluster_multiplicities_sha256')==json_digest(plan)
            and receipt.get('replicates')==len(plan) and receipt.get('cluster_count')==len(order)
            and receipt.get('target_count')==len(targets) and receipt.get('draws_per_target')==30,
            'SENS_ARCHIVED_PLAN_ALIGNMENT','Saved plan differs from the original raw BASE cluster order')
    if fixture_mode:
        require(2<=len(plan)<=64 and len(targets)<=32 and len(order)<=32,
                'SENS_FIXTURE_PLAN_BOUNDARY','Synthetic plan exceeds its small fixture boundary')
    else:
        require(len(plan)==2000 and len(order)==1744 and len(targets)==5000,
                'SENS_OPERATIONAL_PLAN_SHAPE','Expected the saved 2000 x 1744 BASE multiplicities')
    return targets,keys,order,plan


def admit_inputs(common,configurations,*,fixture_mode):

    require(type(fixture_mode) is bool,'SENS_MODE','Explicit Boolean mode required')
    exact_keys(common,COMMON_KEYS,'common inputs')
    exact_keys(configurations,CFGS,'complete matrix')
    for cfg in CFGS:
        exact_keys(configurations[cfg],CFG_KEYS,cfg+' inputs')
    source=parse_source_bytes(common['source_bytes'])
    rids,source=adapter._population(common['canonical_rids'],source,fixture_mode)
    source_hash=identity(common['source_bytes'])['sha256']
    if fixture_mode:
        require(len(rids)<=64,'SENS_FIXTURE_BOUNDARY','Synthetic population exceeds 64 constructed rows')
    else:
        ctx=PINS['context']
        require(source_hash==ctx['raw_source_sha256']
                and json_digest(common['hierarchy_tables'])==ctx['hierarchy_tables_json_sha256']
                and json_digest({c:configurations[c]['transformation_by_name'] for c in CFGS[1:]})
                    ==ctx['named_transformations_json_sha256'],
                'SENS_FROZEN_SOURCE_CONTEXT','Source bytes, hierarchies or named transformations differ')
    _pin(common['target_receipt'],'target_sample_receipt.json',fixture_mode)
    _pin(common['noise_receipt'],'noise_receipt.json',fixture_mode)
    targets,keys,order,plan=existing_plan(common,source,fixture_mode)
    for scenario in SCENARIOS:
        _,draws=adapter._noise(common['noise_private'],common['noise_receipt'],
                                scenario,len(targets),fixture_mode)
        require(draws==30,'SENS_DRAW_COUNT','All scenarios, including S3, retain all 30 draws')
    master,_=adapter._permutation(common['master_permutation'],len(rids),fixture_mode)

    for cfg in CFGS:
        c=configurations[cfg]
        _pin(c['base_receipt'],'base/'+cfg+'/permutation_receipt.json',fixture_mode)
        _pin(c['base_state'],'base/'+cfg+'/score_state.json',fixture_mode)
        require(c['base_receipt'].get('private_record_json')==identity(legacy.private_record_bytes(c['base_private']))
                and c['base_receipt'].get('score_state_json_sha256')==json_digest(c['base_state']),
                'SENS_BASE_ARTIFACT_ADMISSION','Archived private mapping or BASE state changed')
        require(c['base_receipt'].get('release_validation_receipt_json_sha256')==json_digest(c['release_receipt']),
                'SENS_RELEASE_ADMISSION','Release receipt differs from the archived BASE binding')
        hierarchy=adapter._hierarchies(common['hierarchy_tables'],source,c['transformation_by_name'])
        adapter._release(cfg,source,c['release_rows'],c['is_outlier'],master,hierarchy,
                         c['transformation_by_name'],c['release_receipt'],c['producer_report_bytes'],fixture_mode)
    return {'source':source,'source_hash':source_hash,'targets':targets,
            'cluster_keys':keys,'cluster_order':order,'plan':plan}


def score_arguments(common,cfg,configuration,admitted,scenario,fixture_mode):
    return dict(config_id=cfg,scenario=scenario,canonical_rids=common['canonical_rids'],
        source_rows=admitted['source'],release_rows=configuration['release_rows'],
        is_outlier=configuration['is_outlier'],master_permutation=common['master_permutation'],
        hierarchy_tables=common['hierarchy_tables'],transformation_by_name=configuration['transformation_by_name'],
        target_private=common['target_private'],target_receipt=common['target_receipt'],
        noise_private=common['noise_private'],noise_receipt=common['noise_receipt'],
        release_validation_receipt=configuration['release_receipt'],source_input_sha256=admitted['source_hash'],
        producer_report_bytes=configuration['producer_report_bytes'],fixture_mode=fixture_mode)


def interval(values):
    require(len(values)>=2 and all(type(v) in (int,float) and isfinite(v) for v in values),
            'SENS_INTERVAL_VALUES','Finite paired replicates required')
    ordered=sorted(values);result=[]
    for numerator in (1,39):
        lo,remainder=divmod((len(ordered)-1)*numerator,40)
        a,b=ordered[lo],ordered[min(lo+1,len(ordered)-1)]
        result.append(a+(b-a)*(remainder/40.0))
    return result


def scenario_intervals(point,bootstrap):
    values={c:[r['R_all'] for r in bootstrap[c]['replicates']] for c in CFGS}
    require(len({len(v) for v in values.values()})==1,'SENS_PAIRED_REPLICATES','Replicate counts differ')
    result={'R_all':{},'difference_vs_raw':{},'suppression_differences':{}}
    def entry(positive,negative=None):
        sample=values[positive] if negative is None else [a-b for a,b in zip(values[positive],values[negative])]
        estimate=point[positive]['R_all']-(point[negative]['R_all'] if negative else 0.0)
        return {'point_estimate':estimate,'stability_interval_95':interval(sample)}
    for c in CFGS:
        result['R_all'][c]=entry(c)
        if c!='CFG00': result['difference_vs_raw'][c]=entry(c,'CFG00')
    for no_s,s in PAIRS: result['suppression_differences'][s+'_minus_'+no_s]=entry(s,no_s)
    require(sum(map(len,result.values()))==39,'SENS_INTERVAL_FAMILIES','Expected exactly 39 intervals per scenario')
    return result


def _emit(sink,name,data,private):

    require(callable(sink),'SENS_SINK_REQUIRED','Explicit artifact sink required')
    require(type(data) is bytes,'SENS_SINK_BYTES','Exact bytes required')
    expected=identity(data)
    require(sink(name,data,private=private)==expected,
            'SENS_SINK_ACK','Sink did not acknowledge the exact artifact bytes')
    return expected


def run_matrix(common,configurations,*,sink,fixture_mode):

    admitted=admit_inputs(common,configurations,fixture_mode=fixture_mode)
    before=json_digest({k:v for k,v in common.items() if k!='source_bytes'})
    output={}
    for scenario in SCENARIOS:
        observations={};permuted_observations={};cells={}
        for cfg in CFGS:
            c=configurations[cfg]
            bundle=adapter.prepare_attack_score_state(**score_arguments(common,cfg,c,admitted,scenario,fixture_mode))
            prefix=scenario+'/'+cfg

            artifacts={
                'score_payload':_emit(sink,prefix+'/score_payload.json',adapter._score_payload_bytes(bundle['score_payload']),True),
                'score_state':_emit(sink,prefix+'/score_state.json',public_bytes(bundle['score_state']),False),
                'score_receipt':_emit(sink,prefix+'/score_receipt.json',adapter.score_receipt_bytes(bundle['bounded_receipt']),False)}
            replay=rebind_existing_permutation(canonical_rids=common['canonical_rids'],
                master_permutation=common['master_permutation'],is_outlier=c['is_outlier'],
                release_receipt=c['release_receipt'],base_private=c['base_private'],
                base_receipt=c['base_receipt'],base_state=c['base_state'],score_bundle=bundle,fixture_mode=fixture_mode)
            artifacts['replay']=_emit(sink,prefix+'/replay_receipt.json',replay.receipt_bytes,False)
            cell={'artifacts':artifacts,'evaluations':{}}
            for role in ('ACTUAL','PERMUTED'):
                evaluated=evaluate_with_replay(score_bundle=bundle,replay=replay,
                    canonical_rids=common['canonical_rids'],source_rows=admitted['source'],
                    target_private=common['target_private'],target_receipt=common['target_receipt'],mapping_role=role)
                _emit(sink,prefix+'/'+role.lower()+'_evaluation_private.json',evaluated['private_bytes'],True)
                _emit(sink,prefix+'/'+role.lower()+'_evaluation_receipt.json',evaluated['public_bytes'],False)
                cell['evaluations'][role]=evaluated['public_receipt']
                if role=='ACTUAL':
                    private=evaluated['private_record']
                    require(private['cluster_keys']==admitted['cluster_keys'],
                            'SENS_BASE_CLUSTERS','Scenario changed the original raw cluster tuples')
                    observations[cfg]={k:private[k] for k in ('target_ids','release_ids','success_draws')}
                else:
                    permuted_observations[cfg]={k:evaluated['private_record'][k] for k in ('target_ids','release_ids','success_draws')}
            cells[cfg]=cell
            del bundle,replay,evaluated
        point=risk.produce_point_risk(common['canonical_rids'],admitted['targets'],observations,fixture_mode=fixture_mode)
        permuted_point=risk.produce_point_risk(common['canonical_rids'],admitted['targets'],permuted_observations,fixture_mode=fixture_mode)
        bootstrap=risk.produce_bootstrap_risk(common['canonical_rids'],admitted['targets'],
            admitted['cluster_keys'],admitted['plan'],observations,fixture_mode=fixture_mode)
        guard=bootstrap['payload']['guard_receipt']
        require(point['aggregate_validation_status']==bootstrap['aggregate_validation_status']=='PASS'
                and guard['cluster_order_sha256']==json_digest(admitted['cluster_order'])
                and guard['cluster_multiplicities_sha256']==json_digest(admitted['plan'])
                and guard['replicate_count']==len(admitted['plan']),
                'SENS_RISK_GUARD','Risk guard rejected the frozen common plan')
        for cfg in CFGS:
            for role,consumer in (('ACTUAL',point),('PERMUTED',permuted_point)):
                aggregate=consumer['payload']['aggregates'][cfg]
                evaluated=cells[cfg]['evaluations'][role]
                require(abs(aggregate['R_all']-evaluated['risk_all_estimate'])<=1e-12,
                        'SENS_POINT_BINDING','Evaluator and guarded point risk differ')
        private_audit=canonical({'schema':'rtm-scenario-risk-private-audit/1.0','scenario':scenario,
            'visibility':'PRIVATE_DO_NOT_UPLOAD','base_audit_artifact':common['bootstrap_receipt']['private_audit'],
            'point_consumer':point,'permuted_point_consumer':permuted_point,'bootstrap_consumer':bootstrap})
        audit_id=_emit(sink,scenario+'/risk_audit_private.json',private_audit,True)
        output[scenario]={'cells':cells,'point_risk':point['payload']['aggregates'],
            'permuted_point_risk':permuted_point['payload']['aggregates'],
            'interval_count':39,'intervals':scenario_intervals(point['payload']['aggregates'],bootstrap['payload']['aggregates']),
            'zero_retained_replicates':{c:sum(r['N_ret']==0 for r in bootstrap['payload']['aggregates'][c]['replicates']) for c in CFGS},
            'guard_summary':{k:guard[k] for k in ('status','assertion_family','scope','cluster_count',
                'replicate_count','cluster_order_sha256','cluster_multiplicities_sha256')},
            'full_guard_json_digest':json_digest(guard),'private_risk_audit_artifact':audit_id}
        _emit(sink,scenario+'/scenario_receipt.json',public_bytes(output[scenario]),False)
        del observations,permuted_observations,point,permuted_point,bootstrap,private_audit
    require(before==json_digest({k:v for k,v in common.items() if k!='source_bytes'}),
            'SENS_INPUT_MUTATED','Shared archived inputs changed during matrix evaluation')
    result={'schema':'rtm-sensitivity-matrix-candidate/1.0','effective_protocol':'v1.2.4',
        'approved_specification_record':'RTM-S1-S4-DIAGNOSTICS-SPECIFICATION-01',
        'base_repository_head_context':PINS['context']['repository_head'],
        'base_repository_tree_context':PINS['context']['repository_tree'],
        'result':'PASS_WITHIN_SYNTHETIC_SCOPE' if fixture_mode else 'COMPUTED_PENDING_CONTROLLER_ACCEPTANCE',
        'scope':'SYNTHETIC_FIXTURE' if fixture_mode else 'SUPPLIED_OPERATIONAL_ARTIFACTS',
        'scenario_count':4,'configuration_count':17,'cell_count':68,'interval_count':156,
        'replicates':len(admitted['plan']),'draws_per_target':30,
        'base_cluster_order_sha256':json_digest(admitted['cluster_order']),
        'base_cluster_multiplicities_sha256':json_digest(admitted['plan']),
        'interval_interpretation':'conditional_cluster_resampling_stability',
        'monte_carlo_uncertainty_covered':False,'simultaneous_coverage_claimed':False,
        'scenarios':output,'new_rng_generation':False,'execution_authorization_conferred':False,
        'durable_storage_verified_by_core':False,'gate_d_e_accepted':False,'end_to_end_pass':False}
    _emit(sink,'matrix_receipt.json',public_bytes(result),False)
    return result
