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


class hashStorageAuthentication:
    l_hashListFromLog=[]

    def launchProcess(self,command):
        '''
        Function launch multiple instance of a process
        :param command:
        :return:
        '''
        l_processId=subprocess.Popen([command], stdout=subprocess.PIPE,
                                                   shell=True).pid
        time.sleep(10)

    def killProcess(self,process):
        '''
        Function to kill all instances of a process
        :param process:
        :return:
        '''
        l_option1 = '/im'
        l_option2 = '/f'
        try:
            l_p = subprocess.Popen(['taskkill', l_option1, process, l_option2], stdout=subprocess.PIPE, shell=True)
            return True
        except Exception as l_error:
            g_objlog.my_logger(g_logFile, 'Error in StopTool Function : {}'.format(l_error), 'a',
                               level=Test_custom_logger.logging.ERROR)
            return l_error

    def readHashlistLog(self):
        '''
        Class function to read Tool Hash List log
        :return:
        '''
        with open(g_objpath.getFilePath('tmToolHashLogPath'),'r') as l_file_pointer :
            l_tmpHashList = l_file_pointer.readlines()
            g_objlog.my_logger(g_logFile, 'Getting Hash List from Tool Log', 'a',
                               level=Test_custom_logger.logging.INFO)
            for l_item in l_tmpHashList:
                self.l_hashListFromLog.append(l_item.replace('\n',''))

            return self.l_hashListFromLog

    def checkCacheAuthentication(self,command):

        l_baseHashList = self.readHashlistLog()
        print('\n',len(l_baseHashList))
        time.sleep(10)
        self.launchProcess(command)
        time.sleep(10)
        l_newHashList = self.readHashlistLog()
        print(len(l_newHashList))
        for l_item in l_newHashList:
            if l_item not in l_baseHashList:
                print(l_item)
                #l_newHashID = l_item
        #print(l_newHashID)


    

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

    l_process = 'notepad.exe'
    l_objtoolFunction = toolStartStop()
    l_objtoolFunction.startTool()
    print('Waiting for 10 seconds to capture logs',end='\r')
    time.sleep(10)
    os.chdir(g_testPath)

    l_objhashAuth = hashStorageAuthentication()
    l_objhashAuth.checkCacheAuthentication(l_process)
    l_objhashAuth.killProcess(l_process)

    '''g_objlog.my_logger(g_logFile, 'Starting 1st Test - Checking Hash Storage Mechanism', 'a',
                       level=Test_custom_logger.logging.INFO)
    l_funcCall1=l_objhashstore.compareHashLogvscmd()

    if l_funcCall1==True:
        g_objlog.my_logger(g_resultFile, '{} : PASS'.format(l_objhashstore.compareHashLogvscmd.__name__), 'w',
                           level=Test_custom_logger.logging.INFO)
    else:
        g_objlog.my_logger(g_resultFile, '{} : Fail with Error {} not found'.format(l_objhashstore.compareHashLogvscmd.__name__,l_funcCall1), 'a',
                           level=Test_custom_logger.logging.ERROR)
    tmToolOperation(100)

    g_objlog.my_logger(g_logFile, 'Starting 2nd Test - Checking Hash Update Mechanism', 'a',
                       level=Test_custom_logger.logging.INFO)

    l_funcCall2 = l_objhashstore.checkHashruntimelog()
    print(l_funcCall2)

    if l_funcCall2==True:
        g_objlog.my_logger(g_resultFile, '{} : PASS'.format(l_objhashstore.checkHashruntimelog.__name__), 'w',
                           level=Test_custom_logger.logging.INFO)
    else:
        g_objlog.my_logger(g_resultFile, '{} : Fail with Error {} not found'.format(l_objhashstore.checkHashruntimelog.__name__,l_funcCall2), 'a',
                           level=Test_custom_logger.logging.ERROR)'''

    l_objtoolFunction.stopTool()
    return 0

if __name__=='__main__':
    main()