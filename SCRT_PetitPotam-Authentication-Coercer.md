* rule_id: 535
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1658397007681
* modify_time: 1658397007681
* severity: SEV_040_HIGH
* source: frank.bussink@scrt.ch
* comment: SCRT BIOC to detect MS-EFSR RPC calls
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: 63ff8e3fd8bf3c789420808d33882451
* indicator_text: dataset = xdr_data 
| filter EVENT_TYPE = RPC_CALL
| filter event_rpc_interface_uuid = "{C681D488-D850-11D0-8C52-00C04FD90F7E}" 
| filter ((action_rpc_func_opnum = 0) or (action_rpc_func_opnum = 4) or (action_rpc_func_opnum = 5) or (action_rpc_func_opnum = 6) or (action_rpc_func_opnum = 7) or (action_rpc_func_opnum = 12)) 
* name: SCRT-PetitPotam-Authentication-Coercer
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$EVENT_TYPE", "OPERATOR": "EQ", "RIGHT": "$RPC_CALL", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_rpc_interface_uuid", "OPERATOR": "EQ", "RIGHT": "{C681D488-D850-11D0-8C52-00C04FD90F7E}", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"OR": [{"OR": [{"OR": [{"OR": [{"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 0, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 4, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 5, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 6, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 7, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 12, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1658397007681
