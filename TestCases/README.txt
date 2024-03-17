===================================================================================================
## Project Title
===================================================================================================
Threat Monitor Tool - QA Automated Test Plan & Test Cases

===================================================================================================
## Summary
===================================================================================================
This Project is part of a QA Test automation Coding challenge , which aims at developing a Tool for capturing system runtime process and their Hash ID.
The tool is purely developed using Python V3.12
This Directory is Purely dedicated for storing Automated tests , its Logs & Results for sole purpose of checking the accuracy and reliability of the Tool.
The Test Plan excel sheet contains total of 10 Test Cases planned. But out of those only 6 could be Automated. Rest are just manual test cases which can be automated in future.

===================================================================================================
## Steps to run Test SCripts
====================================================================================================
- Before Running Please install following Pre-requiste software & modules :

   1. Python
   2. Psutil module 5.9.8 (pip install psutil)

-Test Plan is mentioned in the below file :
   1.Test_plan.xlsx

- Run the following Automated Test scripts in command prompt as Administartor :
   1.Check_Tool_Health.py
   2.Check_Runtime_Process_Capture.py
   3.Check_Duplicate_Process_Entry.py
   4.Check_Hash_Storing_Mechanism.py - This script covers two test cases from the Test Plan (1.Check_Hash_Storing_Mechanism , 2.Check_Hash_Update_Mechanism)

- Make sure following files are present in the current directory :
   1.Test_filePath.py
   2.Test_custom_logger.py
   3.Test_file_path.json

- Make sure following Directory are present in the current directory:
   1. .\Logs
   2. .\Results

- After downloading from git repository, it is not recomended to move any of the scripts, files and directories 
  for simpler use.

================================================================================================
## Contact
================================================================================================
Email : trusharm2019@gmail.com
