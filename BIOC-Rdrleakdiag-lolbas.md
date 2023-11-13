* rule_id: 503
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1638350429925
* modify_time: 1638350456574
* severity: SEV_030_MEDIUM
* source: frank.bussink@scrt.ch
* comment: Privesc cdpsgshims.dll
* status: ENABLED
* category: PRIVILEGE_ESCALATION
* ## Indicator ##
  * runOnCGO: False
  * investigationType: FILE_EVENT
* ### Investigation ###
* #### File_Event ####
* ##### Filter #####
* ###### And ######
* ###### Or ######
  * SEARCH_FIELD: event_sub_type
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: 1
  * isExtended: False
  * SEARCH_FIELD: event_sub_type
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: 2
  * isExtended: False
  * SEARCH_FIELD: event_sub_type
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: 3
  * isExtended: False
  * SEARCH_FIELD: event_sub_type
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: 6
  * isExtended: False
  * SEARCH_FIELD: action_file_name
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: cdpsgshims.dll
* ###### Extra_Fields ######
  * isExtended: False
  * node: attributes
* indicator_md5: a5d8fbe26ddbd7f48f8b4f660ed52866
* indicator_text: File action type = create, read, rename, write AND file name = cdpsgshims.dll
* name: SCRT cdpsgshims.dll created to disk
* mitre_technique_id_and_name: T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
* mitre_tactic_id_and_name: TA0004 - Privilege Escalation
* mitre_tactic_id: TA0004
* mitre_technique_id: T1574.001
* ## Btp_Rule ##
* ### Agent_Os_Windows ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: SCRT cdpsgshims.dll created to disk
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: SCRT cdpsgshims.dll created to disk
  * biocId: 503
  * additionalData: {}
  * rule_data: (deftemplate file_operation_503 (slot cid)) (defrule file_operation_503 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_open*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "cdpsgshims.dll")))) (not (file_operation_503 (cid ?cid))) => (assert (file_operation_503 (cid ?cid))))
* ### Agent_Os_Mac ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: SCRT cdpsgshims.dll created to disk
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: SCRT cdpsgshims.dll created to disk
  * biocId: 503
  * additionalData: {}
  * rule_data: (deftemplate file_operation_503 (slot cid)) (defrule file_operation_503 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_open*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "cdpsgshims.dll")))) (not (file_operation_503 (cid ?cid))) => (assert (file_operation_503 (cid ?cid))))
* ### Agent_Os_Linux ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: SCRT cdpsgshims.dll created to disk
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: SCRT cdpsgshims.dll created to disk
  * biocId: 503
  * additionalData: {}
  * rule_data: (deftemplate file_operation_503 (slot cid)) (defrule file_operation_503 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_open*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq (lowcase ?file_name) "cdpsgshims.dll")))) (not (file_operation_503 (cid ?cid))) => (assert (file_operation_503 (cid ?cid))))
* btp_rule_name: file_operation_503
* is_preventable: 1
* supported_os: 7
* btp_validation_error: None
* xql: None
* is_xql: False
* query_tables: None
* rule_id: 502
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1638350268266
* modify_time: 1638353935456
* severity: SEV_040_HIGH
* source: frank.bussink@scrt.ch
* comment: Created by F. Bussink SCRT
* status: ENABLED
* category: EXECUTION
* ## Indicator ##
  * runOnCGO: True
  * investigationType: PROCESS_EXECUTION_EVENT
* ### Investigation ###
* #### Process_Execution_Event ####
* ##### Filter #####
* ###### And ######
  * SEARCH_FIELD: agent_os_type
  * SEARCH_TYPE: NEQ
  * SEARCH_VALUE: 4
* ###### Extra_Fields ######
  * isExtended: False
  * node: xdr_agent
  * SEARCH_FIELD: action_process_signature_status
  * SEARCH_TYPE: COMPLEX_EQ
  * SEARCH_VALUE: {"COLLECTION_TYPE": "SIGNATURE_STATUS", "COLLECTION_VALUE": "SIGNATURE_SIGNED"}
* ###### Extra_Fields ######
  * isExtended: False
  * SEARCH_FIELD: action_process_signature_vendor
  * SEARCH_TYPE: REGEX
  * SEARCH_VALUE: Jetico.*
* ###### Extra_Fields ######
  * isExtended: False
* indicator_md5: ca1b0c73d6ed6af725f54b8f6165913f
* indicator_text: Process action type = execution AND process execution signature = Signed AND process execution signer =~ Jetico.* Host host os != linux
* name: SCRT JETICO Signed binary
* mitre_technique_id_and_name: 
* mitre_tactic_id_and_name: 
* mitre_tactic_id: 
* mitre_technique_id: 
* ## Btp_Rule ##
* ### Agent_Os_Windows ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: SCRT JETICO Signed binary
* ###### Tactic_Id ######
* ###### Technique_Id ######
  * biocRuleName: SCRT JETICO Signed binary
  * biocId: 502
  * additionalData: {}
  * rule_data: (deftemplate process_start_502 (slot cid)) (defrule process_start_502 (process_start (is_sign ?is_sign) (cid ?cid) (signer_name ?signer_name &: (and (eq ?is_sign ?*signature_state_signed*) (regex (lowcase ?signer_name) "jetico.*" 0)))) (not (process_start_502 (cid ?cid))) => (assert (process_start_502 (cid ?cid))))
* btp_rule_name: process_start_502
* is_preventable: 1
* supported_os: 1
* btp_validation_error: WINDOWS_SUPPORT_ONLY
* xql: None
* is_xql: False
* query_tables: None
* rule_id: 393
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1684854242506
* modify_time: 1684854242506
* severity: SEV_040_HIGH
* source: frank.bussink@e-xpertsolutions.com
* comment: This is trigguered when a TGS has been request for the canary account (in attempt to bruteforce the password)
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: 8b554c9ad93cfd962b8cfa237fc99914
* indicator_text: dataset = xdr_data // Using the xdr dataset
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4769
| alter ServiceName = json_extract(action_evtlog_data_fields,"$.ServiceName") 
| alter ServiceName = trim(ServiceName,"\"")
| alter TicketEncryptionType = json_extract(action_evtlog_data_fields,"$.TicketEncryptionType")
| alter TicketOptions= json_extract(action_evtlog_data_fields,"$.TicketOptions")
| alter TargetUserName= json_extract(action_evtlog_data_fields,"$.TargetUserName")
| alter IpAddress= json_extract(action_evtlog_data_fields,"$.IpAddress")
| alter TicketEncryptionTypeName = ""
| alter TicketEncryptionTypeName  = if(TicketEncryptionType CONTAINS "0x1", "DES-CBC-CRC", TicketEncryptionTypeName)
| alter TicketEncryptionTypeName  = if(TicketEncryptionType CONTAINS "0x3", "DES-CBC-MD5", TicketEncryptionTypeName )
| alter TicketEncryptionTypeName  = if(TicketEncryptionType CONTAINS "0x11", "AES128-CTS-HMAC-SHA1-96", TicketEncryptionTypeName)
| alter TicketEncryptionTypeName  = if(TicketEncryptionType CONTAINS "0x12", "AES256-CTS-HMAC-SHA1-96", TicketEncryptionTypeName)
| alter TicketEncryptionTypeName  = if(TicketEncryptionType CONTAINS "0x17", "RC4-HMAC", TicketEncryptionTypeName)
| alter TicketEncryptionTypeName  = if(TicketEncryptionType CONTAINS "0x18", "RC4-HMAC-EXP", TicketEncryptionTypeName)	
| alter TicketOptionsName = ""
| alter TicketOptionsName  = if(TicketOptions CONTAINS "0x40810010", "Forwardable, Renewable, Canonicalize, Renewable-ok", TicketOptionsName)
| alter TicketOptionsName  = if(TicketOptions CONTAINS "0x40810000", "Forwardable, Renewable, Canonicalize", TicketOptionsName)
| alter TicketOptionsName  = if(TicketOptions CONTAINS "0x60810010", "Forwardable, Forwarded, Renewable, Canonicalize, Renewable-ok", TicketOptionsName)
| filter (ServiceName = "sqlsvc") 
* name: BIOC-Kerberoasting Canary account
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"AND": [{"LEFT": "$event_type", "OPERATOR": "EQ", "RIGHT": "$ENUM.EVENT_LOG", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}, {"LEFT": "$action_evtlog_event_id", "OPERATOR": "EQ", "RIGHT": 4769, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"ADD_FIELDS": {"fields": [{"name": "ServiceName", "source": {"function": "json_extract", "parameters": ["$action_evtlog_data_fields", "$.ServiceName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "ServiceName", "source": {"function": "string_trim", "parameters": ["$ServiceName", "\""]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionType", "source": {"function": "json_extract", "parameters": ["$action_evtlog_data_fields", "$.TicketEncryptionType"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketOptions", "source": {"function": "json_extract", "parameters": ["$action_evtlog_data_fields", "$.TicketOptions"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TargetUserName", "source": {"function": "json_extract", "parameters": ["$action_evtlog_data_fields", "$.TargetUserName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "IpAddress", "source": {"function": "json_extract", "parameters": ["$action_evtlog_data_fields", "$.IpAddress"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": ""}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketEncryptionType", "OPERATOR": "CONTAINS", "RIGHT": "0x1", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "DES-CBC-CRC"]], "$TicketEncryptionTypeName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketEncryptionType", "OPERATOR": "CONTAINS", "RIGHT": "0x3", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "DES-CBC-MD5"]], "$TicketEncryptionTypeName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketEncryptionType", "OPERATOR": "CONTAINS", "RIGHT": "0x11", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "AES128-CTS-HMAC-SHA1-96"]], "$TicketEncryptionTypeName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketEncryptionType", "OPERATOR": "CONTAINS", "RIGHT": "0x12", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "AES256-CTS-HMAC-SHA1-96"]], "$TicketEncryptionTypeName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketEncryptionType", "OPERATOR": "CONTAINS", "RIGHT": "0x17", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "RC4-HMAC"]], "$TicketEncryptionTypeName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketEncryptionTypeName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketEncryptionType", "OPERATOR": "CONTAINS", "RIGHT": "0x18", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "RC4-HMAC-EXP"]], "$TicketEncryptionTypeName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketOptionsName", "source": ""}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketOptionsName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketOptions", "OPERATOR": "CONTAINS", "RIGHT": "0x40810010", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "Forwardable, Renewable, Canonicalize, Renewable-ok"]], "$TicketOptionsName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketOptionsName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketOptions", "OPERATOR": "CONTAINS", "RIGHT": "0x40810000", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "Forwardable, Renewable, Canonicalize"]], "$TicketOptionsName"]}}]}}, {"ADD_FIELDS": {"fields": [{"name": "TicketOptionsName", "source": {"function": "switch_case", "parameters": [[[{"filter": {"OR": [{"LEFT": "$TicketOptions", "OPERATOR": "CONTAINS", "RIGHT": "0x60810010", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}, "Forwardable, Forwarded, Renewable, Canonicalize, Renewable-ok"]], "$TicketOptionsName"]}}]}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$ServiceName", "OPERATOR": "EQ", "RIGHT": "sqlsvc", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1684854242506
* rule_id: 388
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1683118061196
* modify_time: 1694168591898
* severity: SEV_040_HIGH
* source: frank.bussink@e-xpertsolutions.com
* comment: SCRT BIOC to detect MS-EFSR RPC calls
* status: ENABLED
* category: CREDENTIAL_ACCESS
* indicator: None
* indicator_md5: f6473e3c9013984ff967251d17884890
* indicator_text: dataset = xdr_data 
| filter EVENT_TYPE = RPC_CALL
| filter event_rpc_interface_uuid = "{C681D488-D850-11D0-8C52-00C04FD90F7E}" 
| filter ((action_rpc_func_opnum = 0) or (action_rpc_func_opnum = 4) or (action_rpc_func_opnum = 5) or (action_rpc_func_opnum = 6) or (action_rpc_func_opnum = 7) or (action_rpc_func_opnum = 8) or (action_rpc_func_opnum = 9) or (action_rpc_func_opnum = 12) or (action_rpc_func_opnum = 13) or(action_rpc_func_opnum = 15)) 
* name: BIOC-PetitPotam-Authentication-Coercer
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: 0
* btp_validation_error: UNSUPPORTED_XQL
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"OR": [{"LEFT": "$EVENT_TYPE", "OPERATOR": "EQ", "RIGHT": "$RPC_CALL", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$event_rpc_interface_uuid", "OPERATOR": "EQ", "RIGHT": "{C681D488-D850-11D0-8C52-00C04FD90F7E}", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"OR": [{"OR": [{"OR": [{"OR": [{"OR": [{"OR": [{"OR": [{"OR": [{"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 0, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 4, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 5, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 6, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 7, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 8, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 9, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 12, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 13, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}, {"LEFT": "$action_rpc_func_opnum", "OPERATOR": "EQ", "RIGHT": 15, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_indicator_last_modified_ts: 1694168591976
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
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
* rule_id: 395
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1643316022296
* modify_time: 1643316022296
* severity: SEV_030_MEDIUM
* source: frank.bussink@scrt.ch
* comment: Possible RBCD Attack. A computer account creates another Computer account.
https://www.bussink.net/rbcd-webclient-attack/
* status: ENABLED
* category: PRIVILEGE_ESCALATION
* indicator: None
* indicator_md5: a446f0072748b2bb6dadc13136560211
* indicator_text: dataset = xdr_data 
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id =  4741
| filter action_evtlog_message ~= ".*A computer account was created.*"
| alter AccountName = arrayindex(regextract(action_evtlog_message, ".*Account Name:.*?(\w.*)\r\n"),0)
| filter AccountName ~= ".*\$.*"
* name: SCRT-RBCD-Attack
* mitre_technique_id_and_name: 
* mitre_tactic_id_and_name: 
* mitre_tactic_id: 
* mitre_technique_id: 
* btp_rule: None
* btp_rule_name: None
* is_preventable: 0
* supported_os: None
* btp_validation_error: None
* xql: {"tables": ["xdr_data"], "stages": [{"FILTER": {"filter": {"AND": [{"LEFT": "$event_type", "OPERATOR": "EQ", "RIGHT": "$ENUM.EVENT_LOG", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}, {"LEFT": "$action_evtlog_event_id", "OPERATOR": "EQ", "RIGHT": 4741, "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$action_evtlog_message", "OPERATOR": "REGEX", "RIGHT": ".*A computer account was created.*", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}, {"ADD_FIELDS": {"fields": [{"name": "AccountName", "source": {"function": "array_item", "parameters": [{"function": "regexp_extract_all", "parameters": ["$action_evtlog_message", ".*Account Name:.*?(\\w.*)\\r\\n"]}, 0]}}]}}, {"FILTER": {"filter": {"OR": [{"LEFT": "$AccountName", "OPERATOR": "REGEX", "RIGHT": ".*\\$.*", "FILTER_DIALECT": "EXTENDED_FILTER_OBJ"}]}}}]}
* is_xql: True
* query_tables: ["xdr_data"]
* rule_id: 395
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1687879280170
* modify_time: 1687879288067
* severity: SEV_030_MEDIUM
* source: frank.bussink@e-xpertsolutions.com
* comment: https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/
No known legit usage
* status: ENABLED
* category: CREDENTIAL_ACCESS
* ## Indicator ##
  * runOnCGO: True
  * investigationType: PROCESS_EXECUTION_EVENT
* ### Investigation ###
* #### Process_Execution_Event ####
* ##### Filter #####
* ###### And ######
  * SEARCH_FIELD: action_process_image_name
  * SEARCH_TYPE: REGEX
  * SEARCH_VALUE: rdrleakdiag
* ###### Extra_Fields ######
  * isExtended: False
  * node: attributes
  * SEARCH_FIELD: action_process_image_command_line
  * SEARCH_TYPE: REGEX
  * SEARCH_VALUE: .*rdrleakdiag.*\/fullmemdmp.*
* ###### Extra_Fields ######
  * isExtended: False
* indicator_md5: 7a67171bb15f69cb9e42881b5e49c089
* indicator_text: Process action type = execution AND target process cmd =~ .*rdrleakdiag.*\/fullmemdmp.* AND target process name =~ rdrleakdiag
* name: BIOC-Rdrleakdiag-lolbas-command
* mitre_technique_id_and_name: T1003.001 - OS Credential Dumping: LSASS Memory
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003.001
* ## Btp_Rule ##
* ### Agent_Os_Windows ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-Rdrleakdiag-lolbas-command
* ###### Tactic_Id ######
  * 0: TA0006
* ###### Technique_Id ######
  * 0: T1003.001
  * biocRuleName: BIOC-Rdrleakdiag-lolbas-command
  * biocId: 395
  * additionalData: {}
  * rule_data: (deftemplate process_start_395 (slot cid)) (defrule process_start_395 (process_start (process_image_name ?process_image_name) (cid ?cid) (command_line ?command_line &: (and (regex ?process_image_name "rdrleakdiag" 0) (regex ?command_line ".*rdrleakdiag.*\\/fullmemdmp.*" 0)))) (not (process_start_395 (cid ?cid))) => (assert (process_start_395 (cid ?cid))))
* ### Agent_Os_Mac ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-Rdrleakdiag-lolbas-command
* ###### Tactic_Id ######
  * 0: TA0006
* ###### Technique_Id ######
  * 0: T1003.001
  * biocRuleName: BIOC-Rdrleakdiag-lolbas-command
  * biocId: 395
  * additionalData: {}
  * rule_data: (deftemplate process_start_395 (slot cid)) (defrule process_start_395 (process_start (process_image_name ?process_image_name) (cid ?cid) (command_line ?command_line &: (and (regex ?process_image_name "rdrleakdiag" 0) (regex ?command_line ".*rdrleakdiag.*\\/fullmemdmp.*" 0)))) (not (process_start_395 (cid ?cid))) => (assert (process_start_395 (cid ?cid))))
* ### Agent_Os_Linux ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-Rdrleakdiag-lolbas-command
* ###### Tactic_Id ######
  * 0: TA0006
* ###### Technique_Id ######
  * 0: T1003.001
  * biocRuleName: BIOC-Rdrleakdiag-lolbas-command
  * biocId: 395
  * additionalData: {}
  * rule_data: (deftemplate process_start_395 (slot cid)) (defrule process_start_395 (process_start (process_image_name ?process_image_name) (cid ?cid) (command_line ?command_line &: (and (regex (lowcase ?process_image_name) "rdrleakdiag" 0) (regex (lowcase ?command_line) ".*rdrleakdiag.*\\/fullmemdmp.*" 0)))) (not (process_start_395 (cid ?cid))) => (assert (process_start_395 (cid ?cid))))
* btp_rule_name: process_start_395
* is_preventable: 1
* supported_os: 7
* btp_validation_error: None
* xql: None
* is_xql: False
* query_tables: None
* rule_indicator_last_modified_ts: 1687879280170
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
