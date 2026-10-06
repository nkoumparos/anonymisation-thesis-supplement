import io
import zipfile

from io_boundary import require,identity,strict_json,METADATA_POLICY
from protected_sink import bounded_public


def verify_native_review(raw,package_identity,input_identity,context):
    require(type(raw) is bytes and 0<len(raw)<=500000,'NATIVE_REVIEW_BYTE_BOUND')
    names={'SYNTHETIC_VALIDATION.json','FILE_CONTROLLER_PROOF.json','PREFLIGHT_RECEIPT.json','REVIEW_MANIFEST.json'}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(len(archive.infolist())==4 and set(archive.namelist())==names
                and sum(i.file_size for i in archive.infolist())<=500000
                and not any(i.flag_bits&1 for i in archive.infolist()),'NATIVE_REVIEW_MEMBER_SET')
        blobs={name:archive.read(name) for name in names}
    objects={n:bounded_public(v) for n,v in blobs.items()}
    manifest=objects['REVIEW_MANIFEST.json']
    require(manifest['schema']=='rtm-reader-controller-preflight-review/1.0'
            and manifest['files']=={n:identity(v) for n,v in blobs.items() if n!='REVIEW_MANIFEST.json'}
            and manifest['actual_private_payloads_included'] is False
            and manifest['constructed_private_fixture_files_included'] is False,'NATIVE_REVIEW_MANIFEST_BINDING')
    receipt=objects['PREFLIGHT_RECEIPT.json'];tests=objects['SYNTHETIC_VALIDATION.json'];proof=objects['FILE_CONTROLLER_PROOF.json']
    require(receipt['schema']=='rtm-reader-controller-public-preflight/1.0'
            and receipt.get('tool_revision')=='2.0' and receipt.get('metadata_reader_policy')==METADATA_POLICY
            and receipt['result']=='READER_CONTROLLER_PREFLIGHT_PASS' and receipt['mode']=='NATIVE_WINDOWS'
            and receipt['package']['manifest_artifact']==package_identity
            and receipt['input_contract']==input_identity,'NATIVE_REVIEW_PACKAGE_BINDING')
    require(receipt['test_artifacts']=={n:identity(blobs[n]) for n in ('SYNTHETIC_VALIDATION.json','FILE_CONTROLLER_PROOF.json')},
            'NATIVE_REVIEW_TEST_BINDING')
    runtime={'implementation':'cpython','python':'3.12.10','platform':'win32'}
    require(receipt['runtime']==tests['runtime']==runtime,'NATIVE_REVIEW_RUNTIME')
    require(receipt['repository']['result']=='PASS' and receipt['repository']['head']==context['repository_head']
            and receipt['repository']['tree']==context['repository_tree']
            and len(receipt['repository']['public_sources'])==8,'NATIVE_REVIEW_REPOSITORY')
    require(tests['result']=='PASS_WITHIN_NEW_SYNTHETIC_SCOPE' and tests['tests_run']==40 and tests['tool_revision']=='2.0'
            and tests['failures']==tests['errors']==tests['skips']==0 and len(tests['cases'])==40
            and len({c['test'] for c in tests['cases']})==40
            and all(c['result']=='PASS' for c in tests['cases']),'NATIVE_REVIEW_TEST_COMPLETENESS')
    require(proof['result']=='PASS_WITHIN_NEW_SYNTHETIC_FILE_CONTROLLER_SCOPE'
            and proof['constructed_file_count']==80 and proof['cell_count']==68 and proof['interval_count']==156
            and proof['new_private_files']==208 and proof['new_public_files']==432
            and proof['scenario_tie_diagnostics_count']==68
            and proof['reader_metadata_checks']['metadata_policy']==METADATA_POLICY
            and proof['reader_metadata_checks']['verified_reads']>0
            and proof['native_acl_policy']['native_windows_acl_used'] is True
            and proof['native_acl_policy']['native_acl_calls']>0
            and proof['native_acl_policy']['user_sid_sha256']==receipt['native_user_sid_sha256']
            and type(receipt['native_user_sid_sha256']) is str and len(receipt['native_user_sid_sha256'])==64,
            'NATIVE_REVIEW_FILE_CONTROLLER_PROOF')
    require(proof['fresh_target_noise_sigma_producers_blocked'] is True and proof['base_rescoring_blocked'] is True
            and proof['actual_private_payload_reads'] is False and proof['actual_experimental_execution'] is False
            and receipt['operational_authorization_conferred'] is False
            and receipt['actual_private_payload_reads'] is False and receipt['actual_sensitivity_execution'] is False
            and receipt['gate_d_e_accepted'] is False and receipt['end_to_end_pass'] is False,
            'NATIVE_REVIEW_SCOPE')
    return {'artifact':identity(raw),'user_sid_sha256':receipt['native_user_sid_sha256'],
            'result':'VALIDATED_NEW_NATIVE_PREFLIGHT_ARCHIVE'}
