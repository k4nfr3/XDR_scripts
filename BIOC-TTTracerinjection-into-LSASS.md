* rule_id: 392
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1684329642854
* modify_time: 1684329724525
* severity: SEV_040_HIGH
* source: frank.bussink@e-xpertsolutions.com
* comment: Tttracer is a Windows tool which can trace memory on any process. Here it was injected into LSASS, which is highly suspicious except in case of troubleshooting with Microsoft
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: 794b6fd75a9fce80e01417d11131152f
* indicator_text: preset = xdr_injection 
| filter (action_remote_process_image_name = "lsass.exe") 
| filter (actor_process_image_name = "ttdinject.exe") 
* name: BIOC-TTTracer on LSASS
* mitre_technique_id_and_name: T1003.001 - OS Credential Dumping: LSASS Memory
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003.001
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: 0
* btp_validation_error: UNSUPPORTED_XQL
* xql: {"presets": ["xdr_injection"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$action_remote_process_image_name", "OPERATOR": "EQ", "RIGHT": "lsass.exe", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$actor_process_image_name", "OPERATOR": "EQ", "RIGHT": "ttdinject.exe", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1684329642854
