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
