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
