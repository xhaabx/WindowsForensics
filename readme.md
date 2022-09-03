### Python Forensics Tool

This tool is to help gather forensic data from a host.

Options:  
    LogEvents    
        - This will retrieve the Windows event logs, recently opened applications, and generic system logs.  
    Network  
        - This will retrieve local ARP, DNS, IP Interface, Routing, and active SMB Sessions  
    Process  
        - This will retrieve information about running processes with their repectives handles and DLLs  
    Regkeys  
        - This will query a list of important registry keys for threat hunting.    
    Memory  
        - This will make a memory(ram) dump (Better than CB)
    BrowserHistory  
        - This will retrieve the navigation history databases for Chrome, Firefox, and Edge.   
    AutoRun  
        - This will retrieve the Autorun applications in the systems based on Registry Keys and ASEP.  
    All  
        - This will run all the above arguments (Take about 2 minutes)  
    zipdir   
        - This will zip any directory in the host and move to the current directory.   
    NetworkDump
    	- This will create a network dump of an specific size. (may take a while)

Example:   
Python_Forensics.exe BrowserHistory  
Python_Forensics.exe BrowserHistory AutoRun  
Python_Forensics.exe zipdir c:\Users\Gabriel\Documents  
Python_Forensics.exe NetworkDump 50

In the end, the script generates a .zip file with the gathered information. 

## Information Gathered: 

#### LogEvents
	- Backup Windows Event Logs
		- Security
		- Application 
		- Setup 
		- System
	- Windows Recent oppened files
		- C:\Users\User\AppData\Roaming\Microsoft\Windows\Recent

#### Network
	- arp -a
	- ipconfig /displaydns
	- ipconfig /all
	- route print
	- netstat -nao
	- net session

#### Process
	- handle.exe /accepteula -a 
	- tasklist
	- Listdlls.exe /accepteula
	- wmic process

#### Regkeys
	- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
	- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
	- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
	- HKCU\SOFTWARE\Classes
	- HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
	- HKLM\SYSTEM\CurrentControlSet\Enum\USB 
	- HKLM\SYSTEM\MountedDevices
	- HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
	- HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
	- HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Shares
	- HKLM\SYSTEM\CurrentControlSet\Control\FileSystem
	- HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces
	- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\HomeGroup             

#### BrowserHistory
	- C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\History
	- C:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\History
	- C:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\profile\places.sqlite
	- hindsight.exe -i <chrome_path> -o <folder>\<user>_chrome_forensics

#### Memory
	- winpmem_mini_x64_rc2.exe -d <folder>\RAM_Dump.raw 

#### NetworkDump 
	- netsh trace start capture=yes maxSize=<size> traceFile=trace-output.etl

#### AutoRun
	- autorunsc64.exe /accepteula -a * -c -h -s '\*' -nobanner
	- schtasks /query /FO CSV /v