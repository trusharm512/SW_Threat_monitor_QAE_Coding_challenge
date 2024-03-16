- Before Running Please install following Pre-requiste software & modules :

   1. Python
   2. Psutil module 5.9.8 (pip install psutil)

- Run the Tool(Python script) in Administartor mode
- Make sure custom_logger.py & conf.json are present in the same folder as the running script.
- For Logs make sure TM_tool_Logs directory is present in the script base directory

================================================================================================
================================================================================================
TOOL_CODE_ALGORITHM :

1.Initialize all the log files

2.Use psutil library - to extract runtime process data (pid,name,system current time)& path

3.Run powershell command -inside python script - to get path for which psutil library is not working properly

4.Use haslib module - passing process path to get the hash id's

5.Create multidimesional data structure to store (hash id:(pid:,pname:,time:)) - store hash id (Base Cache)

6.Run an Infinite while loop & wait for keyboard interrupt to break out of loop

7.Repeat Step 2-4

8.Store new hash id(locally) and calculate time difference i.e. local hash id (time) - global hash id (time)
if(check time interval , if < 60 : discrd, >=60 : pop)

9. If new hash id is not in Base cache , add new hash id & updtae  Base cache

 

