'''
Title: Forensics Tool in Python
Author: Gabriel Haab
Date: 8/22/2022
'''

help = """
This tool is to help gather forensic data from a host.

Options:  
    LogEvents    
        - This will retrieve the Windows event logs, recent opened applications, and generic system logs.  
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
Python_Forensics.exe zipdir c:\\Users\\Gabriel\\Documents  
Python_Forensics.exe NetworkDump 50

At the end, the script generates a .zip file with the gathered information. 
"""

import win32evtlog
import socket
import time
import os 
import shutil
import sys
import subprocess

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = os.open(os.devnull, os.O_RDWR)
    
def CompressAndClean(foldername):
    print("\n- - - - Cleaning up")  
    print("Compressing folder..." )
    shutil.make_archive(foldername, 'zip', foldername)
    print("Compressing complete: " + foldername + ".zip") 
    
    print("Cleaning up...\n")
    shutil.rmtree(foldername)

def zipdir(zipfolder,foldername):
    zipfile = zipfolder.split("\\")[-1]
    
    try:
        shutil.make_archive(foldername + "\\" + zipfile, 'zip', zipfolder.replace("\\","\\\\"))
        print("Folder saved on: " + os.getcwd() + "\\" + zipfile + ".zip")
        
    except Exception as err:
        print("Error: " + str(err))

def LogEvents(foldername):
    print("\n- - - - Getting Windows Events Data")   
    
    foldername = foldername + "\\LogEvents"
    os.mkdir(foldername)
    
    print("Creating: " + "Application_" + str(socket.gethostname()) + ".evtx")
    hand = win32evtlog.OpenEventLog("localhost", "Application")
    win32evtlog.BackupEventLog(hand, foldername + "\Application_" + str(socket.gethostname()) + ".evtx")
    
    print("Creating: " + "Security_" + str(socket.gethostname()) + ".evtx")
    hand = win32evtlog.OpenEventLog("localhost", "Security")
    win32evtlog.BackupEventLog(hand, foldername + "\Security_" + str(socket.gethostname()) + ".evtx")
    
    print("Creating: " + "Setup_" + str(socket.gethostname()) + ".evtx")
    hand = win32evtlog.OpenEventLog("localhost", "Setup")
    win32evtlog.BackupEventLog(hand, foldername + "\Setup_" + str(socket.gethostname()) + ".evtx")
    
    print("Creating: " + "System_" + str(socket.gethostname()) + ".evtx")
    hand = win32evtlog.OpenEventLog("localhost", "System")
    win32evtlog.BackupEventLog(hand,foldername + "\System_" + str(socket.gethostname()) + ".evtx")

    for item in os.listdir("C:\\Users"):
        if os.path.isdir("C:\\Users\\" + item):
            # Chrome History
            if os.path.exists("C:\\Users\\" + item + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent"):
                if len(os.listdir("C:\\Users\\" + item + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent")) > 1:
                    print("Creating: " + item + "_RecentOpened.txt")
                    file_pointer = open(foldername + "\\" + item + "_RecentOpened.txt","w")
                    file_pointer.write('\n'.join(os.listdir('C:\\Users\\' + item + '\\AppData\\Roaming\\Microsoft\\Windows\\Recent')))
    
    '''
    print("Creating: " + "AppCompatCacheParser.txt")
    command = "bin\\AppCompatCacheParser.exe --csv "+ foldername +" --csvf AppCompatCacheParser.txt"
    
    with os.popen(command) as f:
        data= f.read()
    '''
    command = [resource_path("bin\\AppCompatCacheParser.exe"), "--csv", foldername, "--csvf", "AppCompatCacheParser.txt"]
    data = subprocess.run(command, stdin=DEVNULL, stderr=DEVNULL)
    

def resource_path(relative_path):
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def Network(foldername):
    
    print("\n- - - - Getting Network Data")
    
    foldername = foldername + "\\Networking"
    os.mkdir(foldername)
    
    commands = [{"filename":"ARP_Cache.txt", "cmdline":["arp","-a"]},
                {"filename":"DNS_Cache.txt", "cmdline":["ipconfig","/displaydns"]},
                {"filename":"IP_Interface.txt", "cmdline":["ipconfig","/all"]},
                {"filename":"route print.txt", "cmdline":["route","print"]},
                {"filename":"netstat.txt", "cmdline":["netstat","-nao"]},
                {"filename":"SMBsession.txt", "cmdline":["net","session"]}]

    for command in commands:
        print("Creating: " + command["filename"])
        filepointer = open(foldername + "\\" + command["filename"] , "w")
        try:
            data = subprocess.check_output(command['cmdline'], stdin=DEVNULL, stderr=DEVNULL)
            filepointer.write(" ".join(command['cmdline']) + "\n")
            filepointer.write(data.decode("utf-8"))
        except Exception as err:
            #print("ERROR: " + str(err))
            filepointer.write("Error running: " + " ".join(command['cmdline']))
        filepointer.close()        

def Process(foldername):
    print("\n- - - - Getting Process Data")   
    
    foldername = foldername + "\\Processes"
    os.mkdir(foldername)

    commands = [{"filename":"Handle.txt", "cmdline": [resource_path("bin\\handle.exe"),"/accepteula","-a"]},
                {"filename":"RunningProcesses.txt", "cmdline":["tasklist"]},
                #{"filename":"ProcDump.txt", "cmdline":"procdump64.exe /accepteula"},
                {"filename":"ListDlls.txt", "cmdline":[resource_path("bin\\Listdlls.exe"),"/accepteula"]},
                {"filename":"WMIC Process.txt", "cmdline":["wmic","process","list","full"]}]
    
    for command in commands:
        print("Creating: " + command["filename"])
        filepointer = open(foldername + "\\" + command["filename"] , "w")
        try:
            data = subprocess.check_output(command['cmdline'], stdin=DEVNULL, stderr=DEVNULL)
            filepointer.write(data.decode("utf-8") )
        except: 
            filepointer.write("Error running: " + command['cmdline'])
        filepointer.close()             

def Regkeys(foldername):
    
    print("\n- - - - Getting RegistryKeys Data")
    
    foldername = foldername + "\\RegKeys"
    os.mkdir(foldername)
    
    RegistryHives = ["HKEY_CLASSES_ROOT",
                     "HKEY_CURRENT_USER",
                     "HKEY_LOCAL_MACHINE\\SAM",
                     "HKEY_LOCAL_MACHINE\\SOFTWARE",
                     "HKEY_LOCAL_MACHINE\\SECURITY",
                     "HKEY_LOCAL_MACHINE\\SYSTEM",
                     "HKEY_USERS",
                     "HKEY_CURRENT_CONFIG"]
                     
    RegistryKey = ["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorersaas",
                   "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                   "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                   "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                   "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                   #"HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell",
                   "HKCU\\SOFTWARE\\Classes",
                   "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                   "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB", 
                   #"HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",
                   "HKLM\\SYSTEM\\MountedDevices",
                   #"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt",
                   #"NTUSER.DAT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Mountpoints2",
                   "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
                   "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                   "HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Shares",
                   "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem",
                   "HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces",
                   #"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList",
                   "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\HomeGroup",
                   #"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory"                   
                   ]

    for key in RegistryKey:
        filename = key.replace('\\','_')
        filename = filename.replace(' ','')
        
        print("Creating: " + filename)
        filepointer = open(foldername + "\\" + filename + ".txt", "w")
        
        try:
            data = subprocess.check_output(['reg', 'query', key, "/s"], stdin=DEVNULL, stderr=DEVNULL)
            filepointer.write(data.decode("utf-8") )
        except: 
            filepointer.write("Error running: " + key['RegistryKey'])
        filepointer.close()  


def BrowserHistory(foldername):
    print("\n- - - - Getting Browser History")
    
    foldername = foldername + "\\BrowserHistory"
    os.mkdir(foldername)
    count = 0
    for item in os.listdir("C:\\Users"):
        if os.path.isdir("C:\\Users\\" + item):
            
            # Chrome History
            default_Chrome_path = "C:\\Users\\" + item + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
            if os.path.exists(default_Chrome_path):
                print("Creating: " + item + "_ChromeHistory.sqlite")
                shutil.copy2(default_Chrome_path, foldername + "\\" + item + "_ChromeHistory.sqlite")
                count = 1
                
                ## Hindsight Forensics Execution
                print("    Running hindsight...")
                try:
                    data = subprocess.check_output([resource_path("bin\\hindsight.exe"), "-i", default_Chrome_path[:-8], "-o",foldername + "\\" + item + "_ChromeForensics"], stdin=DEVNULL, stderr=DEVNULL)
                    os.remove("hindsight.log")
                    print("    Done")
                except: 
                    pass
                    
            # Edge History
            if os.path.exists("C:\\Users\\" + item + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"):
                print("Creating: " + item + "_EdgeHistory.sqlite")
                shutil.copy2("C:\\Users\\" + item + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History",foldername + "\\" + item + "_EdgeHistory.sqlite")      
                count = 1

            # Firefox History
            firefox_profiles = "C:\\Users\\" + item + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
            if os.path.exists(firefox_profiles):
                for profile in os.listdir(firefox_profiles):
                    if os.path.exists(firefox_profiles + "\\" + profile + "\\places.sqlite"):
                        print("Creating: " + item + "_FirefoxHistory.sqlite")
                        shutil.copy2(firefox_profiles + "\\" + profile + "\\places.sqlite",foldername + "\\" + item + "_FirefoxHistory.sqlite")
                        count = 1
    if count == 0: 
        print("No Browsing History Database Found")
        
def Memory(foldername):
    print("\n- - - - Getting memory Data")
    
    foldername = foldername + "\\Memory"
    os.mkdir(foldername)    
    
    try:
        data = subprocess.check_output([resource_path("bin\\winpmem_mini_x64_rc2.exe"), "-d", foldername + "\\RAM_Dump.raw"], stdin=DEVNULL, stderr=DEVNULL)
    except: 
        pass
    
def AutoRun(foldername): 
    print("\n- - - - Getting Auto-Start Extensibility Points (ASEPs) Data")
    
    foldername = foldername + "\\AutoRun"
    os.mkdir(foldername)    
    
    filename = "ASEP.txt"
    print("Creating: " + filename)
    
    command = [resource_path("bin\\autorunsc64.exe"),"/accepteula","-a","*", "-c", "-h", "-s", "'*'", "-nobanner" , ">", foldername + "\\ASEP.txt"]
    #command = resource_path("bin\\autorunsc64.exe") + " /accepteula -a * -c -h -s '*' -nobanner > " + foldername + "\\ASEP.txt"
    #command = "bin\\autorunsc64.exe /accepteula -a * -c -h -s '*' -nobanner >  "

    try:
        data = subprocess.check_output(command, stdin=DEVNULL, stderr=DEVNULL, shell=True) 
        print("Done collecting, start parsing")
    except Exception as err:
        print(err)
        print("Error Running: " + " ".join(command))
  
    fp = open(foldername + "\\ASEP.txt",'r')
    
    filename = "ASEP_Clean.txt"
    
    print("Creating: " + filename)
    filepointer = open(foldername + "\\" + filename, "w")
    
    header = ["Time", "Entry Location", "Entry", "Enabled", "Category", "Profile", "Description", "Signer", "Company", "Image Path", "Version", "Launch String", "MD5", "SHA-1", "PESHA-1", "PESHA-256", "SHA-256", "IMP"]

    for line in fp: 
        tmp_encod = line.replace('\000','')
        tmp_encod = tmp_encod.replace('\n','')
        tmp_line = tmp_encod.split(',')
        if len(tmp_line) > 1 and "Entry Location" not in tmp_line:
            filepointer.write('\n')
            for i in range(len(header)):
                try:
                    filepointer.write(header[i] + ": " + tmp_line[i] + "\n")
                except:
                    filepointer.write(header[i] + ": \n")
    fp.close()
        
      
    print("\n- - - - Getting Scheduled Tasks Data")
    filename = "schtasks.csv"
    
    filepointer = open(foldername + "\\" + filename, "w")  
    print("Creating: " + filename)
    command = ["schtasks","/query","/FO","CSV","/v"]
    
    try:
        data = subprocess.check_output(command, stdin=DEVNULL, stderr=DEVNULL)
        filepointer.write(data.decode("utf-8") )
    except: 
        filepointer.write("Error running: " + command['cmdline'])
    filepointer.close()   
   
def NetworkDump(size,foldername):
    output_file = foldername + "\\trace-output_" + str(size) + ".etl"
    command = ["netsh","trace","start","capture=yes","maxSize=" + str(size),"traceFile=" + output_file]
    try:
        print("Starting packet capture... Press Ctrl-C (Just once - otherwise it crashes the system) to stop.")
        data = subprocess.check_output(command, stdin=DEVNULL, stderr=DEVNULL)
        
        #Check size fo file, since process was started in the background. 
        try:
            while True:
                current_size = round(os.path.getsize(output_file) / 1000000,2)
                print(str(current_size) + " MB ...")
                time.sleep(5)
                if current_size > int(size) - 1:
                    break 
                
        except KeyboardInterrupt:
            print("Terminating the process... ")
        
        command = ["netsh","trace","stop"]
        data = subprocess.run(command, stdin=DEVNULL, stderr=DEVNULL)
        pass        
    
        # Convert to pcap file
        
        #command = resource_path("bin\\etl2pcapng.exe"),"\\trace-output.etl","trace-output.pcapng"
        #data = subprocess.check_output(command, stdin=DEVNULL, stderr=DEVNULL)
        
        print("Done")
        
        
    except Exception as err:
        print(str(err))
        print("Error running: " + " ".join(command))

def manager(args):
    global foldername
    
    print("Starting script...")
    start = time.time()
    
    # Create Folder
    foldername = "Forensics_" + str(socket.gethostname()) + "_" + str(int(time.time()))
    os.mkdir(foldername)
    folderpath = os.getcwd() + "\\" + foldername
    
    possible_arguments = ["All","LogEvents","Network","Process","Regkeys","Memory","BrowserHistory","AutoRun"]
    
    if "zipdir" in args[0]:
        try:
            zipdir(args[1],foldername)
            CompressAndClean(foldername)
        except: 
            print("Incorrect Syntax")
            
    elif "NetworkDump" in args:  
        try:
            NetworkDump(args[1],foldername) 
            CompressAndClean(foldername)
        except: 
            print("Incorrect Syntax")
            
    elif "Help" in args:
        print(help)
        sys.exit()
    
    elif "All" in args:  
        args = possible_arguments[1:]
        

    elif set(args).issubset(possible_arguments):
        for arg in args:
            tmp_string = arg+"(foldername)"
            try:
                eval(tmp_string)
            except Exception as err:
                print("ERROR: " + arg + " - " + str(err))
        
        CompressAndClean(foldername)
        end = time.time()
        print("Process Time: " + str(round(end-start,2)) + " seconds")      
        print("Done")                  
    
    else: 
        print("ERROR: Command Not Found\n\n" + help)        
        sys.exit()  
    
if __name__ == "__main__":    
    if len(sys.argv) == 1: 
        print(help)
    else:
        manager(sys.argv[1:])
        

    
    