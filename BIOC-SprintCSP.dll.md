* rule_id: 387
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1683118009481
* modify_time: 1683797390193
* severity: SEV_030_MEDIUM
* source: frank.bussink@e-xpertsolutions.com
* comment: The StorSvc.dll!SvcRebootToFlashingMode RPC method, calls StorSvc.dll!InitResetPhone which also calls StorSvc.dll!ResetPhoneWorkerCallback, that tries to load SprintCSP.dll. As a result, the creation of this file may be indicative of Local Privilege escalation by DLL hijacking as the StorSvc process runs under NT AUTHORITY\SYSTEM.
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
  * SEARCH_VALUE: 3
  * isExtended: False
  * SEARCH_FIELD: event_sub_type
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: 6
  * isExtended: False
  * SEARCH_FIELD: action_file_name
  * SEARCH_TYPE: EQ
  * SEARCH_VALUE: SprintCSP.dll
* ###### Extra_Fields ######
  * isExtended: False
  * node: attributes
* indicator_md5: f8103c0bb88607a5d23e9c7d1d9adc30
* indicator_text: File action type = create, rename, write AND file name = SprintCSP.dll
* name: SprintCSP.dll created to disk (StorSvc LPE)
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
  * friendlyName: SprintCSP.dll created to disk (StorSvc LPE)
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: SprintCSP.dll created to disk (StorSvc LPE)
  * biocId: 387
  * additionalData: {}
  * rule_data: (deftemplate file_operation_387 (slot cid)) (defrule file_operation_387 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "sprintcsp.dll")))) (not (file_operation_387 (cid ?cid))) => (assert (file_operation_387 (cid ?cid))))
* ### Agent_Os_Mac ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: SprintCSP.dll created to disk (StorSvc LPE)
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: SprintCSP.dll created to disk (StorSvc LPE)
  * biocId: 387
  * additionalData: {}
  * rule_data: (deftemplate file_operation_387 (slot cid)) (defrule file_operation_387 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "sprintcsp.dll")))) (not (file_operation_387 (cid ?cid))) => (assert (file_operation_387 (cid ?cid))))
* ### Agent_Os_Linux ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: SprintCSP.dll created to disk (StorSvc LPE)
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: SprintCSP.dll created to disk (StorSvc LPE)
  * biocId: 387
  * additionalData: {}
  * rule_data: (deftemplate file_operation_387 (slot cid)) (defrule file_operation_387 (file_operation (sub_type ?sub_type) (cid ?cid) (file_name ?file_name &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq (lowcase ?file_name) "sprintcsp.dll")))) (not (file_operation_387 (cid ?cid))) => (assert (file_operation_387 (cid ?cid))))
* btp_rule_name: file_operation_387
* is_preventable: 1
* supported_os: 7
* btp_validation_error: None
* xql: None
* is_xql: False
* query_tables: None
* rule_indicator_last_modified_ts: 1683118009481
