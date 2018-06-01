
![Flow diagram](https://4.bp.blogspot.com/-oNlrrT7z5NE/WwvaFw2TNqI/AAAAAAAABC8/LibASUHyk2o_kaQx7j-REC5ucPoqgPopQCLcBGAs/s1600/atd%2Bsubmit.jpg "Flow diagram")


# atdsubmit
Python app that monitors a folder submitting new files to McAfee ATD Sandboxing solution for inspection.

## Usage
atdsubmit.py [-ip ATD_IP_Address] [-u ATD_Username] [-p ATD_Password] [-m folder_to_monitor]

## Description
atdsubmit.py is a multi-threaded application that uses a separate sets of threads for the following processes:

1. Monitor the folder passed as an argument for new files.
2. Calculate the period of time not connectig to the ATD and manage heartbeats connections to the ATD Server to maintain connection open.
3. Submit samples to the ATD server

The application includes following feautures:

* At first execution is able to detect current files on the folder to monitor to not upload them to the ATD box
* When an new file detection event is detected, is able to detect if the file has been partially copied (for instance big files that take a while to complete the copy operation), delegating the submit operation of the file to a second process that executes every 5 minutes.
* Every five minutes, pending files are analyzed and submitted to the ATD server, a maximum size filter (120MB) is also considered
* If in a period of five minutes the application has not submitted any file to the ATD server, it heartbeats the ATD server to maintain conenction open.
* All information related to the execution of the application is stored in a log file in the /log folder on the same path from where the application is launched.



