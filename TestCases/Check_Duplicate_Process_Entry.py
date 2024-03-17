import signal,sys,time
import subprocess,os
import os.path
import Test_filePath,Test_custom_logger

class toolStartStop:
    l_pid = 0
    def startTool(self):
        '''
        Class function to Start the Threat monitor tool
        :return:
        '''
        print('Threat Monitor tool started Successfully')
        g_objlog.my_logger(g_logFile, 'Inside StartTool function', 'a',
                           level=Test_custom_logger.logging.INFO)
        try:
            l_toolFilePath = g_objpath.getFilePath('tmToolPath')
            os.chdir(os.path.dirname(l_toolFilePath))
            g_objlog.my_logger(g_logFile, 'Changing From Testcase dir to Tool dir for setting Environment', 'a',
                               level=Test_custom_logger.logging.INFO)
            g_objlog.my_logger(g_logFile, 'Current working Directory is set to : {}'.format(os.getcwd()), 'a',
                               level=Test_custom_logger.logging.INFO)
            l_subprocessOutput = subprocess.Popen(['python', os.path.basename(l_toolFilePath)], stdout=subprocess.PIPE,
                                                  shell=False)
            self.l_pid = l_subprocessOutput.pid
            g_objlog.my_logger(g_logFile, 'Process ID of Thread monitor Tool : {}'.format(self.l_pid), 'a',
                               level=Test_custom_logger.logging.INFO)
            return True

        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StartTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)
            return l_error

    def stopTool(self):
        '''
        Class Function to Kill the Threat monitor Tool
        :return:
        '''
        print('Threat Monitor tool terminated Successfully')
        g_objlog.my_logger(g_logFile, 'Inside StopTool function', 'a',
                           level=Test_custom_logger.logging.INFO)
        try:
            os.kill(self.l_pid,signal.SIGINT)
            return True
        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)
            return l_error

class checkDuplicateProcessEntry :

    l_processNameFromToolLogList=[]
    l_processId=0
    def captureRuntimeProcessFromToolLog(self):
        '''
        CLass function to capture process details from Threat monitor tool logs
        :return:
        '''
        g_objlog.my_logger(g_logFile, 'Capturing Process from Threat monitor Tool Process runtime log', 'a',
                           level=Test_custom_logger.logging.INFO)
        with open(g_objpath.getFilePath('tmToolProcessLogPath'),'r') as l_filePointer:
            try:
                l_processToolLogOutputList = l_filePointer.readlines()
                if l_processToolLogOutputList == []:
                    print('Tool Process log is empty , waiting for 30 sec more',end='\r')
                    time.sleep(30)
                    l_processToolLogOutputList = l_filePointer.readlines()

                for l_processLogOutputList in l_processToolLogOutputList:
                    l_substr1 = 'name:'
                    l_substr2 = ','
                    l_position1 = l_processLogOutputList.find(l_substr1)
                    l_position2 = l_processLogOutputList.find(l_substr2, l_position1)
                    self.l_processNameFromToolLogList.append(
                        l_processLogOutputList[l_position1 + len(l_substr1):l_position2])

                return self.l_processNameFromToolLogList

            except Exception as l_error:
                g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                                   level=Test_custom_logger.logging.ERROR)


    def launchDuplicateProcess(self,command):
        '''
        Function launch multiple instance of a process
        :param command:
        :return:
        '''
        l_processId=subprocess.Popen([command], stdout=subprocess.PIPE,
                                                   shell=True).pid
        g_processIdList.append(l_processId)

    def killDuplicateProcess(self,process):
        '''
        Function to kill all instances of a process
        :param process:
        :return:
        '''
        print(g_processIdList)
        l_option1 = '/im'
        l_option2 = '/f'
        try:
            l_p = subprocess.Popen(['taskkill', l_option1, process, l_option2], stdout=subprocess.PIPE, shell=True)
            return True
        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)
            return l_error


    def checkDuplicateProcessEntry(self,process):
        '''
        Function to check duplicate process entry on logs
        :param process:
        :return:
        '''
        self.l_newProcessNameLogList = self.captureRuntimeProcessFromToolLog()
        print(self.l_newProcessNameLogList)
        if self.l_newProcessNameLogList.count(process) > 1 :
            return False
        else:
            print(True,process,self.l_newProcessNameLogList.count(process))
            return True




def main():
    global g_testPath
    global g_resultFile
    global g_logFile
    global g_objlog
    global g_objpath
    global g_processIdList
    g_objlog = Test_custom_logger.CLogger()
    g_objpath = Test_filePath.filePath()
    g_testPath = os.path.dirname(os.path.abspath(sys.argv[0]))
    g_resultFile = os.path.abspath(g_objpath.getFilePath('testResultPath')) + '\\' + os.path.basename(
        sys.argv[0]).replace('py', 'txt')
    g_logFile = os.path.abspath(g_objpath.getFilePath('testLogPath')) + '\\' + os.path.basename(sys.argv[0]).replace(
        'py', 'log')
    g_objlog.my_logger(g_logFile, 'All Path set : {} {} {}'.format(g_testPath,g_resultFile,g_logFile), 'w',
                       level=Test_custom_logger.logging.INFO)
    g_objlog.my_logger(g_logFile, 'Starting Test Inside Main function()', 'a',
                       level=Test_custom_logger.logging.INFO)

    '''
    Starting the Test with Calling all required Class functions
    '''
    l_process = 'notepad.exe'
    l_objtoolFunction = toolStartStop()
    l_objtoolFunction.startTool()
    print('Waiting for 10 seconds to capture logs', end='\r')
    time.sleep(10)
    os.chdir(g_testPath)
    l_objcheckDupProcessEntry = checkDuplicateProcessEntry()
    print('\n Launching multiple instance of same process')
    g_processIdList = []
    for l_count in range(20):
        l_objcheckDupProcessEntry.launchDuplicateProcess(l_process)
    time.sleep(20)
    l_funcCall1 = l_objcheckDupProcessEntry.checkDuplicateProcessEntry(l_process)
    if l_funcCall1 == True :
        g_objlog.my_logger(g_resultFile, '{} : PASS'.format(l_objcheckDupProcessEntry.checkDuplicateProcessEntry.__name__), 'w',
                           level=Test_custom_logger.logging.INFO)
    else:
        g_objlog.my_logger(g_resultFile, '{} : FAIL with Error {}'.format(l_objcheckDupProcessEntry.checkDuplicateProcessEntry.__name__, l_funcCall1),
                           'w',
                           level=Test_custom_logger.logging.ERROR)

    l_objcheckDupProcessEntry.killDuplicateProcess(l_process)
    l_objtoolFunction.stopTool()

    return 0

if __name__=='__main__':
    main()
