* rule_id: 537
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1658410759398
* modify_time: 1658410759398
* severity: SEV_020_LOW
* source: frank.bussink@scrt.ch
* comment: SCRT rule to detect Authentication Coerce PetitPotam on MS-DFSNM Op 12 or Op 13
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: a8d61ecc099487a2152fe07ca680bf06
* indicator_text: dataset = xdr_data
| filter event_type = ENUM.RPC_CALL
| filter (event_rpc_interface_uuid = "{4FC742E0-4A10-11CF-8273-00AA004AE673}" )
| filter ((event_rpc_func_opnum = 12) or (event_rpc_func_opnum = 13))

* name: SCRT_PetitPotam_MS_DFSNM_Authentication_Coerce
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$event_type", "OPERATOR": "EQ", "RIGHT": "$ENUM.RPC_CALL", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_rpc_interface_uuid", "OPERATOR": "EQ", "RIGHT": "{4FC742E0-4A10-11CF-8273-00AA004AE673}", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 12, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}, {"LEFT": "$event_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 13, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1658410759398
