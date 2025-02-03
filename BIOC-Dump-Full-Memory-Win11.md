* rule_id: 376
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1738237230815
* modify_time: 1738573977809
* severity: SEV_040_HIGH
* source: frank.bussink@swissexpertgroup.com
* comment: BIOC Dump full memory containing LSASS process and XDR
* status: ENABLED
* category: CREDENTIAL_ACCESS
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
  * SEARCH_VALUE: 6
  * isExtended: False
  * SEARCH_FIELD: action_file_path
  * SEARCH_TYPE: REGEX
  * SEARCH_VALUE: C:\\Users\\.*\\AppData\\Local\\Microsoft\\Windows\\TaskManager\\LiveKernelDumps\\livedump.DMP
* ###### Extra_Fields ######
  * isExtended: False
  * node: attributes
* indicator_md5: b889659c7f1f3004aa43be20826d5c39
* indicator_text: File action type = create, write AND file path =~ C:\\Users\\.*\\AppData\\Local\\Microsoft\\Windows\\TaskManager\\LiveKernelDumps\\livedump.DMP
* name: BIOC-Full_Kernel_Dump_WIN11
* mitre_technique_id_and_name: T1003 - OS Credential Dumping
* mitre_tactic_id_and_name: TA0006 - Credential Access
* mitre_tactic_id: TA0006
* mitre_technique_id: T1003
* ## Btp_Rule ##
* ### Agent_Os_Windows ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-Full_Kernel_Dump_WIN11
* ###### Tactic_Id ######
  * 0: TA0006
* ###### Technique_Id ######
  * 0: T1003
  * biocRuleName: BIOC-Full_Kernel_Dump_WIN11
  * biocId: 376
  * additionalData: {}
  * rule_data: (deftemplate file_operation_376 (slot cid)) (defrule file_operation_376 (file_operation (sub_type ?sub_type) (cid ?cid) (file_path ?file_path &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_write*)) (regex ?file_path "c:\\\\users\\\\.*\\\\appdata\\\\local\\\\microsoft\\\\windows\\\\taskmanager\\\\livekerneldumps\\\\livedump.dmp" 0)))) (not (file_operation_376 (cid ?cid))) => (assert (file_operation_376 (cid ?cid))))
* ### Agent_Os_Mac ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-Full_Kernel_Dump_WIN11
* ###### Tactic_Id ######
  * 0: TA0006
* ###### Technique_Id ######
  * 0: T1003
  * biocRuleName: BIOC-Full_Kernel_Dump_WIN11
  * biocId: 376
  * additionalData: {}
  * rule_data: (deftemplate file_operation_376 (slot cid)) (defrule file_operation_376 (file_operation (sub_type ?sub_type) (cid ?cid) (file_path ?file_path &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_write*)) (regex ?file_path "c:\\\\users\\\\.*\\\\appdata\\\\local\\\\microsoft\\\\windows\\\\taskmanager\\\\livekerneldumps\\\\livedump.dmp" 0)))) (not (file_operation_376 (cid ?cid))) => (assert (file_operation_376 (cid ?cid))))
* ### Agent_Os_Linux ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-Full_Kernel_Dump_WIN11
* ###### Tactic_Id ######
  * 0: TA0006
* ###### Technique_Id ######
  * 0: T1003
  * biocRuleName: BIOC-Full_Kernel_Dump_WIN11
  * biocId: 376
  * additionalData: {}
  * rule_data: (deftemplate file_operation_376 (slot cid)) (defrule file_operation_376 (file_operation (sub_type ?sub_type) (cid ?cid) (file_path ?file_path &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_write*)) (regex (lowcase ?file_path) "c:\\\\users\\\\.*\\\\appdata\\\\local\\\\microsoft\\\\windows\\\\taskmanager\\\\livekerneldumps\\\\livedump.dmp" 0)))) (not (file_operation_376 (cid ?cid))) => (assert (file_operation_376 (cid ?cid))))
* btp_rule_name: file_operation_376
* is_preventable: 1
* supported_os: 7
* btp_validation_error: None
* xql: None
* is_xql: False
* query_tables: None
* rule_indicator_last_modified_ts: 1738573963756
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
