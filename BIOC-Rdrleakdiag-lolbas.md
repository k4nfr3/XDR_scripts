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
