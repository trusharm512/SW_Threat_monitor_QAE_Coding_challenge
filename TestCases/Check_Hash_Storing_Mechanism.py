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

class checkHashStoringMechanism:
    l_hashListFromLog =[]
    l_hashListFromCmd=[]

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

    def collectHashFromCmd(self):
        '''
        Class function to gather Hash list from System using Powershell cmdlet
        :return:
        '''
        l_command = 'Get-Process |Where-Object Path | Select-Object Path |Sort-Object Path -Unique | ForEach-Object {(Get-FileHash $_.Path -Alg MD5).Hash}'
        l_powershellCommandOutput = subprocess.run(['powershell.exe','-NoProfile',l_command],capture_output=True, text=True)
        g_objlog.my_logger(g_logFile, 'Getting Hash List from Powershell Command', 'a',
                           level=Test_custom_logger.logging.INFO)
        for l_item in l_powershellCommandOutput.stdout.split('\n'):
            if l_item != '':
                self.l_hashListFromCmd.append(l_item.lower())

        return self.l_hashListFromCmd

    def compareHashLogvscmd(self):
        '''
        Class function to check if Tool captured Hash list matches System generated Hash list
        :return:
        '''
        for l_hashlist in self.l_hashListFromCmd:
            if l_hashlist in self.l_hashListFromLog:
                continue
            else:
                g_objlog.my_logger(g_logFile, '{} not in the command prompt hash list'.format(l_hashlist), 'a',
                                   level=Test_custom_logger.logging.ERROR)
                return l_hashlist
                break
        else:
            return True

    def checkHashruntimelog(self):
        '''
        Class Function to check Hash runtime update logs.
        :return:
        '''
        with open(g_objpath.getFilePath('tmToolRuntimeLogPath'), 'r') as l_file_pointer:
            l_hashlist = self.readHashlistLog()
            l_substr1 = [l_hashlist[0] ,'already in Cache','Disacrding']
            l_substr2 = [l_hashlist[0], '60 sec time over', 'Updating Cache']
            l_substr3 = [l_hashlist[0] ,'New Hash','Updating Cache']
            l_rtLog = ''.join(l_file_pointer.readlines())
            if l_hashlist[0] in l_rtLog :
                if all(x in l_rtLog for x in l_substr1):

                    g_objlog.my_logger(g_logFile, 'Hash Runtime log updating properly for {}'.format(l_substr1), 'a',
                                       level=Test_custom_logger.logging.INFO)

                    if all(x in l_rtLog for x in l_substr2):

                        g_objlog.my_logger(g_logFile, 'Hash Runtime log updating properly for {}'.format(l_substr2), 'a',
                                       level=Test_custom_logger.logging.INFO)

                        if all(x in l_rtLog for x in l_substr3):
                            g_objlog.my_logger(g_logFile, 'Hash Runtime log updating properly for {}'.format(l_substr3),
                                               'a',
                                               level=Test_custom_logger.logging.INFO)
                            print(True)
                            return True
                        else:
                            g_objlog.my_logger(g_logFile, '{} not in the hash runtime log'.format(l_substr3),
                                               'a',
                                               level=Test_custom_logger.logging.ERROR)
                            return l_substr3
                    else:
                        g_objlog.my_logger(g_logFile, '{} not in the  hash runtime log'.format(l_substr2), 'a',
                                           level=Test_custom_logger.logging.ERROR)
                        return l_substr2

                else:
                    g_objlog.my_logger(g_logFile, '{} not in the  hash runtime log'.format(l_substr1), 'a',
                                       level=Test_custom_logger.logging.ERROR)
                    return l_substr1



def tmToolOperation(seconds):
    '''
    Function to start and stop the threat monitor tool with desired wait in seconds
    :param seconds:
    :return:
    '''
    l_objtoolFunction = toolStartStop()
    l_objtoolFunction.startTool()
    print('Waiting for {} seconds to capture logs'.format(seconds), end='\r')
    time.sleep(seconds)
    os.chdir(g_testPath)
    l_objtoolFunction.stopTool()


def main():
    global g_testPath
    global g_resultFile
    global g_logFile
    global g_objlog
    global g_objpath
   # global g_hashList
    g_objlog = Test_custom_logger.CLogger()
    g_objpath = Test_filePath.filePath()
    g_testPath = os.path.dirname(os.path.abspath(sys.argv[0]))
    g_resultFile = os.path.abspath(g_objpath.getFilePath('testResultPath')) + '\\' + os.path.basename(
        sys.argv[0]).replace('py', 'txt')
    g_logFile = os.path.abspath(g_objpath.getFilePath('testLogPath')) + '\\' + os.path.basename(sys.argv[0]).replace(
        'py', 'log')
    g_objlog.my_logger(g_logFile, 'All Path set : {} {} {}'.format(g_testPath,g_resultFile,g_logFile), 'w',
                       level=Test_custom_logger.logging.INFO)
    tmToolOperation(10)
    l_objhashstore = checkHashStoringMechanism()
    l_objhashstore.readHashlistLog()
    l_objhashstore.collectHashFromCmd()

    g_objlog.my_logger(g_logFile, 'Starting 1st Test - Checking Hash Storage Mechanism', 'a',
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
                           level=Test_custom_logger.logging.ERROR)

    return 0

if __name__=='__main__':
    main()