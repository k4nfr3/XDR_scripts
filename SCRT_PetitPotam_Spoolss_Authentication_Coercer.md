* rule_id: 535
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1658397007681
* modify_time: 1658410787888
* severity: SEV_020_LOW
* source: frank.bussink@scrt.ch
* comment: SCRT BIOC to detect MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: 2b19fe216d6e1efff594f0453f07dc67
* indicator_text: dataset = xdr_data 
| filter EVENT_TYPE = RPC_CALL
| filter event_rpc_interface_uuid = "{12345678-1234-ABCD-EF00-0123456789AB}" 
| filter ((action_rpc_func_opnum = 65) ) 
* name: SCRT-PetitPotam-Spoolss-Authentication-Coercer
* mitre_technique_id_and_name: 
* mitre_tactic_id_and_name: 
* mitre_tactic_id: 
* mitre_technique_id: 
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: 0
* btp_validation_error: UNSUPPORTED_XQL
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$EVENT_TYPE", "OPERATOR": "EQ", "RIGHT": "$RPC_CALL", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_rpc_interface_uuid", "OPERATOR": "EQ", "RIGHT": "{12345678-1234-ABCD-EF00-0123456789AB}", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 65, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1658404769097
