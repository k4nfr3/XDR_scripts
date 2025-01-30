* rule_id: 402
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1699031533674
* modify_time: 1699031533674
* severity: SEV_030_MEDIUM
* source: frank.bussink@swissexpertgroup.com
* comment: 
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: 11dc07e8da51f64c7d0581cc08c7d588
* indicator_text: dataset = xdr_data
| filter event_type = ENUM.PROCESS 
| filter causality_actor_process_signature_vendor CONTAINS "microsoft" // Only keep cmd.exe or powershell etc...
| alter cmd= action_process_image_command_line // use small length var name
| filter cmd CONTAINS "C:\Windows\NTDS\ntds.dit" or cmd CONTAINS "C:\Windows\System32\config\SYSTEM" or cmd CONTAINS "C:\Windows\System32\config\SAM"
* name: XQL-suspicious-command-line to Critical registry and NTDS file
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"stages":[{"FILTER":{"filter":{"OR":[{"LEFT":"$event_type","OPERATOR":"EQ","RIGHT":"$ENUM.PROCESS","FILTER_DIALECT":"EXTENDED_FILTER_OBJ"}]}}},{"FILTER":{"filter":{"OR":[{"LEFT":"$causality_actor_process_signature_vendor","OPERATOR":"CONTAINS","RIGHT":"microsoft","FILTER_DIALECT":"EXTENDED_FILTER_OBJ"}]}}},{"ADD_FIELDS":{"fields":[{"name":"cmd","source":"$action_process_image_command_line"}]}},{"FILTER":{"filter":{"OR":[{"OR":[{"LEFT":"$cmd","OPERATOR":"CONTAINS","RIGHT":"C:\\Windows\\NTDS\\ntds.dit","FILTER_DIALECT":"EXTENDED_FILTER_OBJ"},{"LEFT":"$cmd","OPERATOR":"CONTAINS","RIGHT":"C:\\Windows\\System32\\config\\SYSTEM","FILTER_DIALECT":"EXTENDED_FILTER_OBJ"}]},{"LEFT":"$cmd","OPERATOR":"CONTAINS","RIGHT":"C:\\Windows\\System32\\config\\SAM","FILTER_DIALECT":"EXTENDED_FILTER_OBJ"}]}}}],"original_query":null,"tables":["xdr_data"]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1699031533674
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
