* rule_id: 379
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1742377058044
* modify_time: 1742377058044
* severity: SEV_040_HIGH
* source: frank.bussink@swissexpertgroup.com
* comment: cdpsgshims.dll file created to disk
* status: ENABLED
* category: PRIVILEGE_ESCALATION
* ## Indicator ##
  * runOnCGO: True
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
* indicator_md5: 1767d03009b9052475a528306e7b66d2
* indicator_text: File action type = create, read, rename, write AND file name = cdpsgshims.dll
* name: ATD-cdpsgshims.dll
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
  * friendlyName: ATD-cdpsgshims.dll
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: ATD-cdpsgshims.dll
  * biocId: 379
  * additionalData: {}
  * rule_data: (deftemplate file_operation_379 (slot cid)) (defrule file_operation_379 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_open*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "cdpsgshims.dll")))) (not (file_operation_379 (cid ?cid))) => (assert (file_operation_379 (cid ?cid))))
* ### Agent_Os_Mac ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: ATD-cdpsgshims.dll
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: ATD-cdpsgshims.dll
  * biocId: 379
  * additionalData: {}
  * rule_data: (deftemplate file_operation_379 (slot cid)) (defrule file_operation_379 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_open*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "cdpsgshims.dll")))) (not (file_operation_379 (cid ?cid))) => (assert (file_operation_379 (cid ?cid))))
* ### Agent_Os_Linux ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: ATD-cdpsgshims.dll
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: ATD-cdpsgshims.dll
  * biocId: 379
  * additionalData: {}
  * rule_data: (deftemplate file_operation_379 (slot cid)) (defrule file_operation_379 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_open*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq (lowcase ?file_name) "cdpsgshims.dll")))) (not (file_operation_379 (cid ?cid))) => (assert (file_operation_379 (cid ?cid))))
* btp_rule_name: file_operation_379
* is_preventable: 1
* supported_os: 7
* btp_validation_error: None
* xql: None
* is_xql: False
* query_tables: None
* rule_indicator_last_modified_ts: 1742377058044
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
