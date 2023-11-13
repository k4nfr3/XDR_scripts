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
