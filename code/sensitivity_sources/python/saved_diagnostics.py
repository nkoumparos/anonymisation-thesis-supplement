from collections import Counter
from fractions import Fraction
from math import isfinite

import attack_adapter as adapter
from common import QIS,json_digest,exact_keys
from diagnostic_core import (FIELDS,equivalence_class_diagnostics,tie_diagnostics,
    eight_qi_tvd,intensity,rational,suppression_salary)
from io_boundary import require,identity
from sensitivity_replay import public_bytes

CONVENTION='type7_unweighted_items'


def base_ties(payload,state,score_receipt,evaluation_receipt,*,fixture_mode):
    adapter._validate_score_bundle(payload,state,score_receipt)
    require(state['scenario']==score_receipt['scenario']=='BASE','SAVED_BASE_SCORE_SCENARIO')
    require(state['draw_count']==30 and (fixture_mode or state['target_count']==5000),
            'SAVED_BASE_SCORE_DIMENSIONS')
    require(evaluation_receipt.get('config_id')==state['config_id'] and evaluation_receipt.get('scenario')=='BASE'
            and evaluation_receipt.get('mapping_role')=='ACTUAL','SAVED_BASE_EVALUATION_BINDING')
    require(evaluation_receipt['score_state_json_sha256']==json_digest(state)
            and evaluation_receipt['score_payload_sha256_before_join']==state['score_payload_sha256']
            ==evaluation_receipt['score_payload_sha256_after_join'],'SAVED_BASE_SCORE_COMMITMENT')
    summary,thresholds=validated_ties(payload)
    require(summary['pair_count']==evaluation_receipt['pair_count']
            and summary['item_count']==evaluation_receipt['attempt_count']
            and summary['abstention_count']==evaluation_receipt['abstention_count'],'SAVED_BASE_ATTEMPT_COUNTS')
    require(all(thresholds[m]==evaluation_receipt['coverage_by_maximum_tie_size'][str(m)]['attempt_count'] for m in thresholds),
            'SAVED_BASE_COVERAGE_COUNTS')
    return {'scope':'SYNTHETIC_FIXTURE' if fixture_mode else 'EXISTING_BASE_SCORES',
        'score_payload_artifact':score_receipt['score_payload_json'],'score_state_json_digest':json_digest(state),
        'existing_evaluation_receipt_json_digest':json_digest(evaluation_receipt),'summary':summary,
        'existing_attempt_and_coverage_counts_match':True,'base_scores_recomputed':False}


def validated_ties(payload):
    require(payload['draw_count']==30,'TIE_DRAW_COUNT')
    sizes=payload['candidate_group_sizes'];membership=payload['candidate_group_id_by_position']
    require(type(sizes) is list and sizes and all(type(x) is int and x>0 for x in sizes)
            and len(sizes)==payload['candidate_group_count'] and sum(sizes)==payload['candidate_row_count']
            and len(membership)==payload['candidate_row_count']
            and all(type(x) is int and 0<=x<len(sizes) for x in membership),'SAVED_BASE_GROUP_SHAPE')
    counts=Counter(membership)
    require([counts[i] for i in range(len(sizes))]==sizes,'SAVED_BASE_GROUP_MULTIPLICITIES')
    records=payload['records'];thin=[];thresholds={m:0 for m in (1,2,5,10)}
    require(len(records)==payload['target_count']*30==payload['score_record_count'],'SAVED_BASE_RECORD_COUNT')
    for offset,row in enumerate(records):
        exact_keys(row,{'target_position','draw_index','maximum_score_float_hex','winner_group_ids','tie_size','attempted'},'saved score record')
        require(type(row['target_position']) is type(row['draw_index']) is int
                and (row['target_position'],row['draw_index'])==divmod(offset,30),'SAVED_BASE_RECORD_ORDER')
        winners=row['winner_group_ids']
        require(type(winners) is list and all(type(i) is int and 0<=i<len(sizes) for i in winners)
                and len(set(winners))==len(winners),'SAVED_BASE_WINNERS')
        size=row['tie_size']
        require(type(size) is int and size==sum(sizes[i] for i in winners)
                and type(row['attempted']) is bool and row['attempted']==(size>0),'SAVED_BASE_TIE_DENOMINATOR')
        try:maximum=float.fromhex(row['maximum_score_float_hex'])
        except (ValueError,TypeError,OverflowError):raise ValueError('SAVED_BASE_MAXIMUM_SCORE') from None
        require(isfinite(maximum) and 0<=maximum<=1 and (maximum>0)==(size>0),'SAVED_BASE_ABSTENTION')
        thin.append({'tie_size':size,'attempted':size>0})
        for m in thresholds:thresholds[m]+=1<=size<=m
    summary=tie_diagnostics(thin,convention=CONVENTION)
    return summary,thresholds


def new_score_ties(raw,scenario,cfg,*,fixture_mode):
    from io_boundary import strict_json
    payload=strict_json(raw)
    require(adapter._score_payload_bytes(payload)==raw,'NEW_SCORE_BYTES_CANONICAL')
    require(payload['record_schema']==adapter.SCORE_PAYLOAD_SCHEMA and payload['result']=='PASS'
            and payload['phase']==adapter.SCORE_PHASE and payload['scenario']==scenario and payload['config_id']==cfg
            and payload['scores_complete'] is True and payload['ground_truth_joined'] is False
            and payload['rid_exposed_to_scorer'] is False,'NEW_SCORE_TIE_BINDING')
    require((fixture_mode and 1<=payload['target_count']<=32) or (not fixture_mode and payload['target_count']==5000),
            'NEW_SCORE_TIE_TARGET_COUNT')
    summary,thresholds=validated_ties(payload)
    return {'schema':'rtm-scenario-tie-diagnostics/1.0','effective_protocol':'v1.2.4',
        'scope':'SYNTHETIC_FIXTURE' if fixture_mode else 'NEW_S1_S4_SCORE_ARTIFACT',
        'scenario':scenario,'config_id':cfg,'score_payload_artifact':identity(raw),'summary':summary,
        'coverage_attempt_counts':{str(k):v for k,v in thresholds.items()},
        'quantile_convention':CONVENTION,'draws_per_target':30,'draws_collapsed':False,
        'scoring_repeated_for_diagnostics':False,'ground_truth_used_for_tie_summary':False,
        'evaluation_receipts':{},'gate_d_e_accepted':False,'end_to_end_pass':False}


def bind_tie_evaluation(ties,receipt):
    require(receipt['scenario']==ties['scenario'] and receipt['config_id']==ties['config_id']
            and receipt['mapping_role'] in ('ACTUAL','PERMUTED')
            and receipt['score_payload_sha256_before_join']==receipt['score_payload_sha256_after_join']
                ==ties['score_payload_artifact']['sha256'],'NEW_TIE_EVALUATION_BINDING')
    summary=ties['summary']
    require(receipt['pair_count']==summary['pair_count'] and receipt['attempt_count']==summary['item_count']
            and receipt['abstention_count']==summary['abstention_count']
            and all(receipt['coverage_by_maximum_tie_size'][k]['attempt_count']==v
                    for k,v in ties['coverage_attempt_counts'].items()),'NEW_TIE_EVALUATION_COUNTS')
    role=receipt['mapping_role'];require(role not in ties['evaluation_receipts'],'DUPLICATE_TIE_EVALUATION')
    ties['evaluation_receipts'][role]=json_digest(receipt)

def profiles(source,flags):
    n=len(source);ns=sum(flags);nr=n-ns;out={}
    require(n>0 and nr>0,'PROFILE_POPULATION')
    for a in FIELDS:
        all_counts=Counter(r[a] for r in source)
        ret=Counter(r[a] for r,f in zip(source,flags) if not f)
        sup=Counter(r[a] for r,f in zip(source,flags) if f)
        values=[]
        for v in sorted(all_counts):
            require(ret[v]+sup[v]==all_counts[v],'PROFILE_PARTITION_COUNT')
            rp=Fraction(ret[v],nr);sp=Fraction(sup[v],ns) if ns else None
            values.append({'value':v,'source_count':all_counts[v],'retained_count':ret[v],
                'suppressed_count':sup[v],'source_proportion':rational(Fraction(all_counts[v],n)),
                'retained_proportion':rational(rp),'suppressed_proportion':rational(sp),
                'suppressed_minus_retained_proportion':rational(sp-rp) if sp is not None else None})
        out[a]=values
    return {'basis':'nine_original_raw_attributes','n_source':n,'n_retained':nr,'n_suppressed':ns,
            'suppressed_status':'DEFINED' if ns else 'NA_NO_SUPPRESSED_ROWS','marginals':out,
            'source_equals_retained_plus_suppressed':True}


def native_country(source,flags,level,cfg):
    matching=[i for i,r in enumerate(source) if r['native-country']=='Holand-Netherlands']
    require(len(matching)==1,'NATIVE_COUNTRY_SINGLETON_COUNT')
    suppressed=flags[matching[0]]
    require(cfg=='CFG00' or suppressed or level>=1,'NATIVE_COUNTRY_SINGLETON_RULE')
    if cfg in tuple('CFG%02d'%i for i in range(1,11)):
        require(level>=1,'NATIVE_COUNTRY_NO_SUPPRESSION_LEVEL')
    return {'source_value':'Holand-Netherlands','source_count':1,'final_level':level,
            'fate':'SUPPRESSED' if suppressed else 'RETAINED','rule_status':'RAW_REFERENCE' if cfg=='CFG00' else 'PASS',
            'private_rid_included':False}


def release_diagnostics(common,cfg,configuration,admitted,base_tie_result,*,fixture_mode):
    source=admitted['source'];c=configuration;flags=c['is_outlier'];levels=c['transformation_by_name']
    require(len(source)==len(flags)==len(c['release_rows']) and all(type(f) is bool for f in flags),
            'DIAGNOSTIC_MASK_ALIGNMENT')
    require(all(r['salary-class'] in ('<=50K','>50K') for r in source),'SALARY_DOMAIN')
    hierarchy=adapter._hierarchies(common['hierarchy_tables'],source,levels)
    published,retained,_=adapter._release(cfg,source,c['release_rows'],flags,common['master_permutation'],hierarchy,
        levels,c['release_receipt'],c['producer_report_bytes'],fixture_mode)
    classes=equivalence_class_diagnostics(retained,convention=CONVENTION)
    gate=c['release_receipt']
    if cfg!='CFG00':
        qi=classes['QI'];full=classes['full']
        require(qi['item_count']==gate['equivalence_class_count']
                and qi['size_sum']==gate['equivalence_class_size_sum']==len(retained)
                and qi['minimum']==gate['equivalence_class_size_min']
                and qi['maximum']==gate['equivalence_class_size_max']
                and qi['unique_rows']==gate['u_qi_unique_rows']==0
                and full['unique_rows']==gate['u_full_unique_rows'],'EXISTING_EC_DIAGNOSTICS_MISMATCH')
        require(abs(float(Fraction(qi['unique_rows'],len(retained)))-gate['u_qi'])<=1e-12
                and abs(float(Fraction(full['unique_rows'],len(retained)))-gate['u_full'])<=1e-12,
                'EXISTING_UNIQUENESS_MISMATCH')
    marginal_ref={};marginal_ret={};joint_ref={};joint_ret={}
    for a in QIS:
        selected=[hierarchy[a]['by_leaf'][r[a]][levels[a]] for r in source]
        marginal_ref[a]=Counter(selected);marginal_ret[a]=Counter(r[a] for r in retained)
        joint_ref[a]=Counter((v,r['salary-class']) for v,r in zip(selected,source))
        joint_ret[a]=Counter((r[a],r['salary-class']) for r in retained)
    marginal=eight_qi_tvd(marginal_ref,marginal_ret);joint=eight_qi_tvd(joint_ref,joint_ret)
    if not any(flags):
        require(marginal['maximum']['numerator']==joint['maximum']['numerator']==0,'ZERO_SUPPRESSION_TVD')
    salary=suppression_salary(len(source),len(retained),sum(r['salary-class']=='>50K' for r in source),
                             sum(r['salary-class']=='>50K' for r in retained))
    if cfg!='CFG00':
        for ours,theirs in (('source_positive_prevalence','source_positive_proportion'),
                            ('retained_positive_prevalence','retained_positive_proportion')):
            require(Fraction(salary[ours]['numerator'],salary[ours]['denominator'])
                    ==Fraction(gate[theirs]['numerator'],gate[theirs]['denominator']),'EXISTING_SALARY_PREVALENCE_MISMATCH')
    result={'schema':'rtm-saved-artifact-diagnostics/1.0','effective_protocol':'v1.2.4','config_id':cfg,
        'scope':'SYNTHETIC_FIXTURE' if fixture_mode else 'EXISTING_FROZEN_ARTIFACTS',
        'result':'PASS_WITHIN_DIAGNOSTIC_SCOPE','source_table_sha256':admitted['source_hash'],
        'release_receipt_json_digest':json_digest(gate),'candidate_order_sha256':json_digest(retained),
        'published_source_indices_sha256':json_digest(published),'transformation_by_name':levels,
        'equivalence_classes':classes,'base_tie_diagnostics':base_tie_result,
        'generalization_G':rational(intensity(levels)),'suppression_and_salary':salary,
        'suppressed_retained_profiles':profiles(source,flags),
        'TVD_marginal':marginal,'TVD_QI_salary':joint,
        'TVD_reference':'full_source_transformed_at_the_same_selected_levels_without_deletion',
        'joint_contingency_tables_published':False,'native_country':native_country(source,flags,levels['native-country'],cfg),
        'base_scores_recomputed':False,'new_arx_model_or_rng_execution':False,'execution_authorization_conferred':False,
        'gate_d_e_accepted':False,'end_to_end_pass':False}
    public_bytes(result)
    return result
