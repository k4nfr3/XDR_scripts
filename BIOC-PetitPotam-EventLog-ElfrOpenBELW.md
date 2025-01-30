* rule_id: 397
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1694169318013
* modify_time: 1694169318013
* severity: SEV_040_HIGH
* source: frank.bussink@e-xpertsolutions.com
* comment: E-XpertSolutions BIOC to detect Coerce project
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: 584883bf13f35adb2d803c0525401140
* indicator_text: dataset = xdr_data 
| filter EVENT_TYPE = RPC_CALL
| filter event_rpc_interface_uuid = "{82273FDC-E32A-18C3-3F78-827929DC23EA}" 
| filter (action_rpc_func_opnum = 9)
* name: BIOC-PetitPotam-EventLog-ElfrOpenBELW
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$EVENT_TYPE", "OPERATOR": "EQ", "RIGHT": "$RPC_CALL", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_rpc_interface_uuid", "OPERATOR": "EQ", "RIGHT": "{82273FDC-E32A-18C3-3F78-827929DC23EA}", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 9, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1694169318013
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
