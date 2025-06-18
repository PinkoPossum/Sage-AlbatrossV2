# Sage-AlbatrossV2
Executable cisco-audit program for grabbing logs of your network devices. The python script will also be available if you prefer.

## A Brief
Sage-Albatross V2 is an improvement on my previous python script. This program is a self-contained network auditing tool to eliminate the time consuming process of manually collecting information from Cisco network devices. By packaging it as an executable it no longer requires the installation of python or the script's dependencies. The program utilizes a user provided list of devices to run diagnostic commands, interpret the results, and present them in a clean and **USEFUL** format. 

## How It Works
The user will create a folder labeled "cisco-audit". Inside the folder the User will create a file called devices.txt. In that file please list the device addresses you wish to audit, make sure to only list one device per line. 

The User then should launch the executable. The program first reads the list of devices afterwhich it will prompt you for the necessary credentials to access these devices: username, password, and an optional "enable" secret. This is done to prevent the storage of hard-coded or plain text sensitive information.

Once the User has entered their credentials the program will make use of multithreading to creat a pool of "workers" that can connect to multiple devices at the same time, rather than going one by one like V1. 

To make the program more useful, it utilizes a python library that allows it to determine what kind of cisco device and IOS version each device is running so that it issues the correct commands.

Lastly, the program will output the collected audit information into a formated .csv file that saves your eyes by presenting the info in a more easy to read way. 

## The Output
The program is configured to collect the data and will present you with:
1. Device Name
2. Device Model
3. Device IOS Version
4. Physical and Virtual Interfaces
5. Operational and Protocol Status
6. Physical Topology of Neighbors
   >> Collects neighbor's name, platform, and int ID
   
The data is then compiled into two distinct and valuable output files, both of which are timestamped to ensure a unique record for each run. The primary output is the network_audit_...csv file. This Comma-Separated Values file is designed to be opened directly in any spreadsheet program, such as Microsoft Excel. Inside, you will find all the collected information organized into clear columns. Each row in the spreadsheet corresponds to a single interface on a single device, providing an incredibly granular view of the network. This format makes analysis effortless. You can immediately filter the sheet to show only interfaces that are in a "down" state, sort by hardware model to inventory all devices of a certain type, or search for connections to a specific critical server.

The second output is the network_audit_...log file. This file serves as a complete and detailed operational diary of the tool's execution. It logs every major step in the process: the initiation of a connection, the detected OS of a device, successful command executions, and, crucially, any errors that were encountered. If the tool fails to connect to a device due to a timeout, or if authentication fails, a clear error message is recorded in this log file. This makes troubleshooting any issues straightforward and provides a comprehensive audit trail that can be reviewed later to see exactly what the tool did and what it found.


