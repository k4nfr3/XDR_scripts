* rule_id: 542
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1669279818847
* modify_time: 1669279818847
* severity: SEV_020_LOW
* source: frank.bussink@scrt.ch
* comment: Might be prone to False Positives. It's just an information
* status: ENABLED
* category: TAMPERING
* indicator: None
* indicator_md5: 4d55807a2ddb8dba6626e2bd329c94ea
* indicator_text: preset = xdr_image_load 
| filter action_module_path ~= ".*\.sys$"
| filter event_type = ENUM.LOAD_IMAGE 
| filter (actor_process_signature_status = SIGNED_INVALID) 
* name: SCRT Hunt for invalid driver signature
* mitre_technique_id_and_name: T1068 - Exploitation for Privilege Escalation
* mitre_tactic_id_and_name: 
* mitre_tactic_id: 
* mitre_technique_id: T1068
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"presets": ["xdr_image_load"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$action_module_path", "OPERATOR": "REGEX", "RIGHT": ".*\\.sys$", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_type", "OPERATOR": "EQ", "RIGHT": "$ENUM.LOAD_IMAGE", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$actor_process_signature_status", "OPERATOR": "EQ", "RIGHT": "$SIGNED_INVALID", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1669279818847
