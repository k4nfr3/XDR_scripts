# XDR_scripts (no longer maintained)

This repo is **no longer maintained !**  (24.02.2025)   
  
All new custom BIOC and custom Correlations rules will be published in a private repository.  
If you want to be added to the private repo, contact me (email, twitter github), and I can add you to do but I require contributions as research is time consuming or a NDA.  
Competing companies have used my signatures without my consent and without mentioning my work.  



##  A few custom BIOC signature
- some LPE(s) 
- PetitPotam (from Coercer)
- privesc on some DLL creation
- Lsass memory dump via microsoft TTTracer

## A few XQL queries which can be used for widgets
- one for detecting Canary accounts (which will be trigguered via Kerberoasting attack)  

## A few XDR Scripts

- ProcDump.py is as you might expect to run a ProcDump on a process pid. pid to be passed as argument. (this is not my code but from somebody I don't know )

- Fullmemorydump.py is as you might expect to run winpmem to get the entire memory dump for Forensic purpose.

## A few XDR Collector Filebeat configurations
  
  
## A Python script uploading IOC to XDR tenant via API rest

- XDR_loldriver.io_update_IOC.py


## My whish list of improvements for Cortex XDR  

- ~~Original filenames field in process events and other data~~ (actor_process_file_original_name for example)
- Driver load signature field (against BYOVD)
- BIOC specific fields to report in a Alert (basically give in the Alert the fields you want to show to the operator)
- Every hour or so, check your own subscription as a ETW provider (against BYOVD)
