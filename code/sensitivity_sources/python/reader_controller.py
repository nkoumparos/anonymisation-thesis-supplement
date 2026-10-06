from pathlib import Path
import time

from common import json_digest
from bounded_reader import BoundedReader,load_matrix_inputs
from io_boundary import BoundaryError,canonical,require,strict_json,write_new,read_metrics
from protected_sink import ProtectedSink
from saved_diagnostics import base_ties,release_diagnostics,new_score_ties,bind_tie_evaluation
from sensitivity_runner import CFGS,run_matrix
from sensitivity_replay import public_bytes
from verify_new_outputs import verify_new_audits


class Progress:
    def __init__(self,callback=None):self.callback=callback or (lambda _:None);self.last=0
    def __call__(self,stage,count=0,force=False):
        if force or time.monotonic()-self.last>=15:
            self.callback({'stage':stage,'committed_artifacts':count});self.last=time.monotonic()


def execute_admitted(contract,public,permit,policy,output,*,public_admission,progress=None,public_postcheck=None):

    stage='CREATE_NEW_PROTECTED_OUTPUT';sink=None;reader=None;tick=Progress(progress)
    try:
        sink=ProtectedSink(output,policy)
        if permit.mode=='operational':
            require(policy.user_sid_sha256==public_admission['native_user_sid_sha256'],
                    'NATIVE_PREFLIGHT_USER_MISMATCH')
        stage='ADMIT_BOUND_INPUT_FILES';tick(stage,force=True)
        reader=BoundedReader(contract,permit,policy)
        stage='READ_EXISTING_BOUND_INPUTS';tick(stage,force=True)
        common,configurations,admitted=load_matrix_inputs(reader,public)
        diagnostic_ids={}
        stage='DERIVE_SAVED_DIAGNOSTICS';tick(stage,force=True)
        for cfg in CFGS:
            payload=reader.json('saved_BASE_scores_'+cfg);p=public['configurations'][cfg]
            ties=base_ties(payload,p['score_state.json'],p['score_receipt.json'],
                           p['actual_evaluation_receipt.json'],fixture_mode=permit.mode=='synthetic')
            diagnostic=release_diagnostics(common,cfg,configurations[cfg],admitted,ties,
                                            fixture_mode=permit.mode=='synthetic')
            require(diagnostic['candidate_order_sha256']==p['score_state.json']['candidate_order_sha256'],
                    'DIAGNOSTIC_CANDIDATE_ORDER_BINDING')
            diagnostic_ids[cfg]=sink('diagnostics/'+cfg+'.json',public_bytes(diagnostic),private=False)
            tick(stage,len(sink.entries));del payload,diagnostic
        receipt={'schema':'rtm-saved-diagnostics-receipt/1.0','result':'PASS_WITHIN_DIAGNOSTIC_SCOPE',
            'mode':permit.mode,'configuration_count':17,'artifacts':diagnostic_ids,
            'quantiles':'type7_unweighted_items','base_score_payloads_read':17,'base_score_payloads_recomputed':0,
            'input_contract_json_digest':json_digest(contract),'new_arx_or_model_execution':False,
            'gate_d_e_accepted':False,'end_to_end_pass':False}
        sink('DIAGNOSTICS_RECEIPT.json',public_bytes(receipt),private=False)
        stage='COMPUTE_NEW_S1_S4';tick(stage,len(sink.entries),True)
        pending_ties={};tie_count=0
        def persisted(name,data,*,private):
            nonlocal tie_count
            result=sink(name,data,private=private)
            parts=name.split('/')
            if len(parts)==3:
                prefix='/'.join(parts[:2]);filename=parts[2]
                if filename=='score_payload.json':
                    require(not pending_ties,'UNFINISHED_PREVIOUS_TIE_DIAGNOSTIC')
                    pending_ties[prefix]=new_score_ties(data,parts[0],parts[1],fixture_mode=permit.mode=='synthetic')
                elif filename in ('actual_evaluation_receipt.json','permuted_evaluation_receipt.json'):
                    ties=pending_ties[prefix];bind_tie_evaluation(ties,strict_json(data))
                    if filename=='permuted_evaluation_receipt.json':
                        require(set(ties['evaluation_receipts'])=={'ACTUAL','PERMUTED'},'BOTH_TIE_EVALUATION_BINDINGS_REQUIRED')
                        sink(prefix+'/tie_diagnostics.json',public_bytes(ties),private=False)
                        del pending_ties[prefix];tie_count+=1
            tick(stage,len(sink.entries));return result
        matrix=run_matrix(common,configurations,sink=persisted,fixture_mode=permit.mode=='synthetic')
        require(tie_count==68 and not pending_ties,'EXACT_68_SCENARIO_TIE_DIAGNOSTICS')
        stage='VERIFY_INPUT_METADATA_AND_ACLS';tick(stage,len(sink.entries),True)
        input_verification=reader.finish()
        stage='VERIFY_NEW_PRIVATE_OUTPUT_ACLS';tick(stage,len(sink.entries),True)
        output_acls=sink.inspect_private_outputs()
        stage='VERIFY_NEW_AUDIT_INTERVALS';tick(stage,len(sink.entries),True)
        verification=verify_new_audits(sink,matrix,public['bootstrap_receipt'])
        stage='VERIFY_PUBLIC_CONTEXT_BEFORE_COMPLETION';tick(stage,len(sink.entries),True)
        postcheck=public_postcheck() if public_postcheck is not None else {'scope':'CONSTRUCTED_TEST_ONLY'}
        result={'schema':'rtm-sensitivity-reader-controller/1.0',
            'result':'COMPUTED_PENDING_INDEPENDENT_REVIEW' if permit.mode=='operational' else 'SYNTHETIC_COMPUTED',
            'mode':permit.mode,'public_admission':public_admission,'public_context_postcheck':postcheck,'input_verification':input_verification,
            'new_output_acl_verification':output_acls,'interval_verification':verification,
            'reader_metadata_checks':read_metrics(),
            'diagnostic_configuration_count':17,'sensitivity_cell_count':68,'sensitivity_interval_count':156,
            'scenario_tie_diagnostics_count':68,'expected_outputs':{'all':640,'private':208,'public':432},'file_policy':policy.summary(),
            'new_scores_persisted_before_ground_truth_join':True,'base_scores_recomputed':False,
            'old_controllers_or_oracle_suites_rerun':False,'new_rng_generation':False,
            'existing_files_or_claims_modified':False,'gate_d_e_accepted':False,'end_to_end_pass':False}
        sink('CONTROLLER_RESULT.json',public_bytes(result),private=False)
        stage='FINALIZE_NEW_OUTPUT';tick(stage,len(sink.entries),True)
        marker=sink.finish()
        return {'result':result,'completion':marker,'sink':sink,'reader':reader,'matrix':matrix}
    except Exception as error:
        code=error.code if isinstance(error,BoundaryError) else 'CONTROLLER_'+type(error).__name__.upper()

        stop={'schema':'rtm-sensitivity-controller-stop/1.0','result':'STOP','stage':stage,'failure_code':code,
            'mode':permit.mode,'committed_artifacts':len(sink.entries) if sink else 0,
            'existing_input_reads_attempted':sum(reader.reads.values()) if reader else 0,
            'preserve_all_partial_outputs_and_consumed_claim':True,'automatic_retry_or_resume':False,
            'gate_d_e_accepted':False,'end_to_end_pass':False}

        if sink is not None:
            try:write_new(sink.root/'STOP.json',canonical(stop),private=True)
            except Exception:pass
        raise BoundaryError(code) from None
