* rule_id: 396
* global_rule_id: NO_ID
* mssp_global_rule_id: None
* insert_time: 1689000053662
* modify_time: 1689000053662
* severity: SEV_030_MEDIUM
* source: frank.bussink@e-xpertsolutions.com
* comment: Netman service has a reference to  wlanapi.dll. This can lead to LPE on 2008R2 and 2019 Servcer. As a result, the creation of this file may be indicative of Local Privilege escalation by DLL hijacking as the svchost process runs under NT AUTHORITY\SYSTEM. More info here : https://itm4n.github.io/windows-server-netman-dll-hijacking/
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
  * SEARCH_VALUE: wlanapi.dll
* ###### Extra_Fields ######
  * isExtended: False
  * node: attributes
  * SEARCH_FIELD: action_file_previous_file_path
  * SEARCH_TYPE: REGEX_NOT
  * SEARCH_VALUE: C:\\Windows\\.*
* ###### Extra_Fields ######
  * isExtended: False
  * node: attributes
* indicator_md5: 6947ad0f538332d518b71e8e83821d8e
* indicator_text: File action type = create, rename, write AND file name = wlanapi.dll AND file previous path !=~ C:\\Windows\\.*
* name: BIOC-wlanapi.dll created to disk (Netman LPE)
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
  * friendlyName: BIOC-wlanapi.dll created to disk (Netman LPE)
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: BIOC-wlanapi.dll created to disk (Netman LPE)
  * biocId: 396
  * additionalData: {}
  * rule_data: (deftemplate file_operation_396 (slot cid)) (defrule file_operation_396 (file_operation (file_name ?file_name) (sub_type ?sub_type) (cid ?cid) (old_file_path ?old_file_path &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "wlanapi.dll") (not (regex ?old_file_path "c:\\\\windows\\\\.*" 0))))) (not (file_operation_396 (cid ?cid))) => (assert (file_operation_396 (cid ?cid))))
* ### Agent_Os_Mac ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-wlanapi.dll created to disk (Netman LPE)
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: BIOC-wlanapi.dll created to disk (Netman LPE)
  * biocId: 396
  * additionalData: {}
  * rule_data: (deftemplate file_operation_396 (slot cid)) (defrule file_operation_396 (file_operation (file_name ?file_name) (sub_type ?sub_type) (cid ?cid) (old_file_path ?old_file_path &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq ?file_name "wlanapi.dll") (not (regex ?old_file_path "c:\\\\windows\\\\.*" 0))))) (not (file_operation_396 (cid ?cid))) => (assert (file_operation_396 (cid ?cid))))
* ### Agent_Os_Linux ###
* #### Signatureconfiguration ####
* ##### Default #####
* ###### Settings ######
  * action: block
  * friendlyName: BIOC-wlanapi.dll created to disk (Netman LPE)
* ###### Tactic_Id ######
  * 0: TA0004
* ###### Technique_Id ######
  * 0: T1574.001
  * biocRuleName: BIOC-wlanapi.dll created to disk (Netman LPE)
  * biocId: 396
  * additionalData: {}
  * rule_data: (deftemplate file_operation_396 (slot cid)) (defrule file_operation_396 (file_operation (file_name ?file_name) (sub_type ?sub_type) (cid ?cid) (old_file_path ?old_file_path &: (and (or (eq ?sub_type ?*file_create_new*) (eq ?sub_type ?*file_rename*) (eq ?sub_type ?*file_write*)) (eq (lowcase ?file_name) "wlanapi.dll") (not (regex (lowcase ?old_file_path) "c:\\\\windows\\\\.*" 0))))) (not (file_operation_396 (cid ?cid))) => (assert (file_operation_396 (cid ?cid))))
* btp_rule_name: file_operation_396
* is_preventable: 1
* supported_os: 7
* btp_validation_error: None
* xql: None
* is_xql: False
* query_tables: None
* rule_indicator_last_modified_ts: 1689000053662
* status_changed_by: None
* status_changed_at: None
* last_status_change_reason: None
