import signal,sys
import subprocess,os
import os.path
import time

import Test_filePath,Test_custom_logger

class checkToolHealth:
    l_pid = 0
    #l_objtoolFilePath = Test_filePath.filePath()

    def startTool(self):
        '''
        Class function to Start the Threat monitor tool
        :return:
        '''
        g_objlog.my_logger(g_logFile, '1st Test- Inside StartTool function', 'a',
                           level=Test_custom_logger.logging.INFO)
        try:
            l_toolFilePath = g_objpath.getFilePath('tmToolPath')
            os.chdir(os.path.dirname(l_toolFilePath))
            g_objlog.my_logger(g_logFile, 'Changing From Testcase dir to Tool dir for setting Environment', 'a',
                               level=Test_custom_logger.logging.INFO)
            g_objlog.my_logger(g_logFile, 'Current working Directory is set to : {}'.format(os.getcwd()), 'a',
                               level=Test_custom_logger.logging.INFO)
            l_subprocessOutput = subprocess.Popen(['python', os.path.basename(l_toolFilePath)], stdout=subprocess.PIPE,shell=False)
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
        g_objlog.my_logger(g_logFile, '2nd Test- Inside StopTool function', 'a',
                           level=Test_custom_logger.logging.INFO)
        try:
            os.kill(self.l_pid, signal.SIGINT)
            return True
        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)
            return l_error

    def checkLogs(self):
        '''
        Class function to check the Threat monitor tool logs after successful run
        :return:
        '''
        g_objlog.my_logger(g_logFile, '3rd Test- Inside checkLogs function', 'a',
                           level=Test_custom_logger.logging.INFO)
        os.chdir(g_testPath)
        g_objlog.my_logger(g_logFile, 'Changing back from Tool dir to Testcase dir for setting Environment', 'a',
                           level=Test_custom_logger.logging.INFO)
        g_objlog.my_logger(g_logFile, 'Current working Directory is set to : {}'.format(os.getcwd()), 'a',
                           level=Test_custom_logger.logging.INFO)
        if os.path.isfile(g_objpath.getFilePath('tmToolProcessLogPath')) and os.path.isfile(g_objpath.getFilePath('tmToolHashLogPath'))\
                and os.path.isfile(g_objpath.getFilePath('tmToolRuntimeLogPath')):
            return True
        else:
            g_objlog.my_logger(g_logFile, 'Error in checkLogs Function', 'a',
                               level=Test_custom_logger.logging.ERROR)
            return 'Log File Missing'


def main():
    '''
    Test case main/entry  function to check successful start ,stop & Logs of Threat monitor tool.
    :return:
    '''
    global g_testPath
    global g_resultFile
    global g_logFile
    global g_objlog
    global g_objpath
    l_objchck = checkToolHealth()
    g_objpath = Test_filePath.filePath()
    g_objlog = Test_custom_logger.CLogger()
    g_testPath = os.path.dirname(os.path.abspath(sys.argv[0]))
    g_resultFile = os.path.abspath(g_objpath.getFilePath('testResultPath'))+'\\'+ os.path.basename(sys.argv[0]).replace('py', 'txt')
    g_logFile = os.path.abspath(g_objpath.getFilePath('testLogPath'))+'\\'+ os.path.basename(sys.argv[0]).replace('py', 'log')

    g_objlog.my_logger(g_logFile, 'All Path set : {} {} {}'.format(g_testPath,g_resultFile,g_logFile), 'w',
                       level=Test_custom_logger.logging.INFO)
    g_objlog.my_logger(g_logFile, 'Starting Test Inside Main function()', 'a',
                       level=Test_custom_logger.logging.INFO)

    '''
    Starting the Test with Calling all required Class functions
    '''

    l_funcCall1=l_objchck.startTool()
    print('Threat Monitor tool started Successfully')

    if l_funcCall1 == True:
        g_objlog.my_logger(g_resultFile,'{} : PASS'.format(l_objchck.startTool.__name__),'w',level=Test_custom_logger.logging.INFO)

    else:
        g_objlog.my_logger(g_resultFile, '{} : FAIL with Error {}'.format(l_objchck.startTool.__name__,l_funcCall1), 'w',
                           level=Test_custom_logger.logging.ERROR)


    print('Running for 20 seconds', end='\r')
    time.sleep(20)

    l_funcCall2 =l_objchck.stopTool()
    print('Threat Monitor tool terminated Successfully')

    if l_funcCall2 == True:
        g_objlog.my_logger(g_resultFile, '{} : PASS'.format(l_objchck.stopTool.__name__), 'a',
                           level=Test_custom_logger.logging.INFO)

    else:
        g_objlog.my_logger(g_resultFile, '{} : FAIL with Error {}'.format(l_objchck.stopTool.__name__, l_funcCall2),
                           'a',
                           level=Test_custom_logger.logging.ERROR)

    l_funcCall3 = l_objchck.checkLogs()

    if l_funcCall3 == True:
        g_objlog.my_logger(g_resultFile, '{} : PASS'.format(l_objchck.checkLogs.__name__), 'a',
                           level=Test_custom_logger.logging.INFO)

    else:
        g_objlog.my_logger(g_resultFile, '{} : FAIL with Error {}'.format(l_objchck.checkLogs.__name__, l_funcCall2),
                           'a',
                           level=Test_custom_logger.logging.ERROR)
    return 0

if __name__=='__main__':
    main()
