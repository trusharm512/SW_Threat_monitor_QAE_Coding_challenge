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

class checkRuntimeProcess:

    l_processNameFromCmdList = []
    l_processNameFromToolLogList = []

    def captureRuntimeProcessUsingCmdlet(self):
        '''
        Class function to capture logs from tasklist cmdlet
        :return:
        '''
        g_objlog.my_logger(g_logFile, 'Capturing Process from Windows command Tasklist', 'a',
                           level=Test_custom_logger.logging.INFO)
        try:
            option1 = '/FO'
            option2 = 'CSV'
            self.l_subprocessOutput = subprocess.Popen(['TASKLIST', option1, option2], stdout=subprocess.PIPE,
                                                       shell=True)
            self.l_processData = str(self.l_subprocessOutput.communicate()[0]).split(',')
            l_substr1 = '\\r\\n\"'
            l_substr2 = '\"'
            for i in self.l_processData:
                if l_substr1 in i:
                    # print(i)
                    l_position1 = i.find(l_substr1)
                    l_position2 = i.find(l_substr2, l_position1 + len(l_substr1))
                    self.l_processNameFromCmdList.append(i[l_position1 + len(l_substr1):l_position2])
           #print(self.l_processNameFromCmdList)

        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)

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

                #print(self.l_processNameFromToolLogList)

            except Exception as l_error:
                g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                                   level=Test_custom_logger.logging.ERROR)



    def checkAllProcessRunning(self):
        '''
        Class function to compare the process details captured from tasklist command & Threat monitor tool process runtime log
        :return:
        '''
        g_objlog.my_logger(g_logFile, 'Comparing Process from Windows command with Tool Process runtime log', 'a',
                           level=Test_custom_logger.logging.INFO)
        try:
            for l_process in self.l_processNameFromToolLogList:
                if l_process in self.l_processNameFromCmdList:
                    continue
                elif l_process[0:3] in ''.join(self.l_processNameFromCmdList):
                    continue
                else:
                    print('{} not in process runtime'.format(l_process))
                    break

            for l_process in self.l_processNameFromCmdList:
                if l_process in self.l_processNameFromToolLogList:
                    continue
                elif l_process[0:3] in ''.join(self.l_processNameFromToolLogList):
                    continue
                else:
                    print('{} not in process runtime'.format(l_process))
                    break

            return True

        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)
            return l_error


def main():

    global g_testPath
    global g_resultFile
    global g_logFile
    global g_objlog
    global g_objpath
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
    l_objtoolFunction = toolStartStop()
    l_objtoolFunction.startTool()
    print('Waiting for 20 seconds to capture logs', end='\r')
    time.sleep(20)
    os.chdir(g_testPath)
    l_objcheckProcessDetails = checkRuntimeProcess()
    print('\n Capturing & Comparing Process')
    l_objcheckProcessDetails.captureRuntimeProcessUsingCmdlet()
    l_objcheckProcessDetails.captureRuntimeProcessFromToolLog()
    l_funcCall1 = l_objcheckProcessDetails.checkAllProcessRunning()
    if l_funcCall1 == True :
        g_objlog.my_logger(g_resultFile, '{} : PASS'.format(l_objcheckProcessDetails.checkAllProcessRunning.__name__), 'w',
                           level=Test_custom_logger.logging.INFO)
    else:
        g_objlog.my_logger(g_resultFile, '{} : FAIL with Error {}'.format(l_objcheckProcessDetails.checkAllProcessRunning.__name__, l_funcCall1),
                           'w',
                           level=Test_custom_logger.logging.ERROR)
    l_objtoolFunction.stopTool()

    return 0

if __name__=='__main__':
    main()
