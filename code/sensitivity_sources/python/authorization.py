from datetime import datetime,timezone
from pathlib import Path
import re

from io_boundary import require,plain,identity,canonical,read_exact,strict_json,write_new

SCHEMA='rtm-s1-s4-reader-controller-authorization/1.0'
OPERATIONS=['read_exact_80_bound_existing_inputs_once','derive_approved_saved_artifact_diagnostics',
    'compute_68_S1_S4_cells_with_saved_randomness','compute_156_intervals_with_saved_BASE_multiplicities',
    'create_protected_new_outputs_and_verify_them','create_public_review_archive']
FORBIDDEN=['new_rng_generation','new_arx_execution','model_retraining','old_controller_rerun',
    'old_oracle_suite_rerun','existing_output_or_acl_modification','gate_d_e_acceptance','end_to_end_pass']


def admit_grant(raw,expected_sha256,*,package_identity,input_identity,native_review_identity,
                head,tree,repository,output,now=None):

    require(type(raw) is bytes and identity(raw)['sha256']==expected_sha256,'AUTHORIZATION_HASH_MISMATCH')
    grant=strict_json(raw)
    keys={'schema','status','authorization_id','authorized_by','single_use','issued_at_utc','expires_at_utc',
        'package_manifest','input_contract','native_preflight_review','repository_head','repository_tree',
        'repository_path','output_path','claim_path','stop_sidecar_path','operations','prohibited'}
    require(type(grant) is dict and set(grant)==keys,'AUTHORIZATION_EXACT_SCHEMA')
    require(grant['schema']==SCHEMA and grant['status']=='APPROVED_FOR_ONE_EXECUTION'
            and grant['authorized_by']=='USER_EXPLICIT_APPROVAL' and grant['single_use'] is True,
            'EXPLICIT_SINGLE_USE_USER_GRANT_REQUIRED')
    require(type(grant['authorization_id']) is str and re.fullmatch(r'AUTH-RTM-S1S4-READER-[A-Z0-9_-]{8,96}',grant['authorization_id']),
            'NEW_SCOPED_AUTHORIZATION_ID_REQUIRED')
    require(grant['operations']==OPERATIONS and grant['prohibited']=={k:True for k in FORBIDDEN},
            'AUTHORIZATION_OPERATION_SCOPE')
    require(grant['package_manifest']==package_identity and grant['input_contract']==input_identity
            and grant['native_preflight_review']==native_review_identity,'AUTHORIZATION_ARTIFACT_BINDING')
    require(grant['repository_head']==head and grant['repository_tree']==tree,'AUTHORIZATION_GIT_BINDING')
    repository=plain(repository);output=plain(output)
    require(Path(grant['repository_path'])==repository and Path(grant['output_path'])==output,
            'AUTHORIZATION_PATH_BINDING')
    claim=output.with_name(output.name+'.CLAIM.json');stop=output.with_name(output.name+'.STOP.json')
    require(Path(grant['claim_path'])==claim and Path(grant['stop_sidecar_path'])==stop,'AUTHORIZATION_SIDECAR_SCOPE')
    try:
        issued=datetime.fromisoformat(grant['issued_at_utc']);expires=datetime.fromisoformat(grant['expires_at_utc'])
        current=now or datetime.now(timezone.utc)
        require(issued.tzinfo is not None and expires.tzinfo is not None and issued<=current<=expires,
                'AUTHORIZATION_TIME_WINDOW')
    except (TypeError,ValueError):raise ValueError('AUTHORIZATION_TIME_WINDOW') from None
    require(not output.exists() and output.parent.is_dir() and not claim.exists() and not stop.exists(),
            'AUTHORIZATION_ALREADY_CONSUMED_OR_OUTPUT_EXISTS')
    require(not output.is_relative_to(repository),'OUTPUT_INSIDE_REPOSITORY_FORBIDDEN')
    return {'grant':grant,'identity':identity(raw),'claim':claim,'stop':stop,'output':output}


def consume_grant(admitted):

    claim={'schema':'rtm-s1-s4-reader-controller-claim/1.0','status':'CONSUMED_DO_NOT_REUSE',
        'authorization_id':admitted['grant']['authorization_id'],'authorization':admitted['identity'],
        'package_manifest':admitted['grant']['package_manifest'],
        'output_path':str(admitted['output']),'automatic_retry_or_resume':False,
        'gate_d_e_accepted':False,'end_to_end_pass':False}
    return write_new(admitted['claim'],canonical(claim),private=False)
