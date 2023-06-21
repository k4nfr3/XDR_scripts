# XDR_scripts

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
