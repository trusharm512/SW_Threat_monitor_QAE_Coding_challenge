import hashlib
import psutil
import subprocess
import json
import custom_logger
import time

class theartMonitor:

    system_processes = {}

    def __init__(self,*log_file_name):
        '''
        threatMonitor class constructor to initialize & instantiate all Log files
        :param log_file_name:
        '''
        for l_files in log_file_name:
            with open(l_files, 'w') as l_filePointer:
                l_filePointer.write('')

    def get_hash(self,processPath):
        '''
        threatMonitor class instance method to get the Hash ID for given process path in parameter
        :param processPath:
        :return:
        '''
        self._processPath=processPath
        with open(self._processPath, 'rb') as l_filePointer:
            l_processPath = l_filePointer.read()
            l_hashId = hashlib.md5(l_processPath).hexdigest()
            return l_hashId

    def run_ps_cmd(self,processName):
        '''
        threatMonitor class instance method to run Powershell commands
        :param processName:
        :return:
        '''
        self._processName = processName
        l_returnVal = ''
        if 'exe' in self._processName:
            l_powershellCommand = 'Get-Process ' + str(self._processName)[:-4] + ' | Format-List Path'
            l_powershellCommandOutput = subprocess.run(['powershell.exe','-NoProfile',l_powershellCommand], capture_output=True, text=True)
            l_formatOutput = l_powershellCommandOutput.stdout.replace('\n', '')
            if len(l_formatOutput.split('Path : ')) > 1:
                l_returnVal = l_formatOutput.split('Path : ')[1]
        else:
            print('Invalid')

        return l_returnVal

    def display_proc_running(self,processLogFile,dictCacheData):
        '''
        threatMonitor class instance method to record runtime process id & name in process_runtime_path log.
        :param processLogFile:
        :param dictCacheData:
        :return:
        '''
        self._processLogFile = processLogFile
        self._dictCacheData = dictCacheData

        with open(self._processLogFile, 'w') as l_filePointer:
            for l_pid,l_pname in theartMonitor.system_processes.items():
                l_filePointer.write('pid:{},name:{},'.format(l_pid,l_pname)+'\n')

        with open(self._processLogFile, 'a') as l_filePointer:
            for l_hid in self._dictCacheData.keys():
                for l_values in self._dictCacheData[l_hid]:
                    l_filePointer.write('{}:{}'.format(l_values, self._dictCacheData[l_hid][l_values])+',')
                l_filePointer.write('\n')

    def process(self):
        '''
        threatMonitor class instance method to get runtime process , their details 1.ID 2.Name 3.Hash ID 4.Time Stamp
        and store them in a datastructure , which is returned by the function.
        :return:
        '''
        l_processes = psutil.process_iter()
        l_dictCache = {}
        l_tempList = []
        for l_process in l_processes:
            try:
                if len(l_process.cmdline()) > 0 and l_process.cmdline()[0] != '':
                    if l_process.name() not in l_tempList:
                        if not l_process.cmdline()[0].startswith('C:\\') or not l_process.cmdline()[0].lower().endswith(
                                '.exe'):
                            l_processpath = self.run_ps_cmd(l_process.name())
                            if l_processpath != '':
                                l_dictprocesDetails = {}
                                l_dictprocesDetails['pid'] = l_process.pid
                                l_dictprocesDetails['name'] = l_process.name()
                                l_dictprocesDetails['stime'] = time.time()
                                l_hashId = self.get_hash(l_processpath)
                                l_dictCache[l_hashId] = l_dictprocesDetails
                            else:
                                theartMonitor.system_processes[l_process.pid] = l_process.name()
                        else:
                            l_dictprocesDetails = {}
                            l_dictprocesDetails['pid'] = l_process.pid
                            l_dictprocesDetails['name'] = l_process.name()
                            l_dictprocesDetails['stime'] = time.time()
                            l_hashId = self.get_hash(l_process.cmdline()[0])
                            l_dictCache[l_hashId] = l_dictprocesDetails

                    l_tempList.append(l_process.name())
                else:
                    theartMonitor.system_processes[l_process.pid] = l_process.name()

            except psutil.AccessDenied:
                theartMonitor.system_processes[l_process.pid] = l_process.name()
        print('Capturing runtime Process & their Hash ID\'s',end='\r')
        return l_dictCache

class cacheMethods():
    _hashLogFile = None
    _dictBaseCache={}
    @classmethod
    def store_cache(cls,hashLogFile,dictCache):
        '''
        Class cacheMethods - class method to store the Hash id in base cache for future use
        :param hashLogFile:
        :param dictCache:
        :return:
        '''
        cls._hashLogFile=hashLogFile
        cls._dictBaseCache = dictCache
        with open(cls._hashLogFile,'w') as l_filePointer:
            for l_hid in cls._dictBaseCache.keys():
                l_filePointer.write(l_hid+'\n')

    @staticmethod
    def update_cache(dictNewCache):
        '''
        Class cacheMethods - static method to get new Hash id cache , calculate the time interval of 60 seconds
        with reference to base Cache & update respectively.
        :param dictNewCache:
        :return:
        '''
        l_log = custom_logger.CLogger()
        for l_hid in dictNewCache.keys():
            if l_hid in cacheMethods._dictBaseCache:
                if dictNewCache[l_hid]['stime']-cacheMethods._dictBaseCache[l_hid]['stime'] < float(60):
                    l_log.my_logger(g_hash_log_out,'Hash {} already in Cache , Disacrding'.format(l_hid),'a',level=custom_logger.logging.INFO)
                    continue
                elif dictNewCache[l_hid]['stime']-cacheMethods._dictBaseCache[l_hid]['stime'] > float(60):
                    cacheMethods._dictBaseCache.pop(l_hid)
                    cacheMethods.store_cache(g_hash_list_out,cacheMethods._dictBaseCache)
                    l_log.my_logger(g_hash_log_out, 'Hash {} 60 sec time over, Updating Cache'.format(l_hid), 'a',level=custom_logger.logging.INFO)
            else:
                cacheMethods._dictBaseCache[l_hid]=dictNewCache[l_hid]
                cacheMethods.store_cache(g_hash_list_out,cacheMethods._dictBaseCache)
                l_log.my_logger(g_hash_log_out, 'New Hash {} found, Updating Cache'.format(l_hid), 'a',level=custom_logger.logging.INFO)

def main():
    '''
    Process Entry Point
    :return:
    '''
    global g_process_log_out
    global g_hash_log_out
    global g_hash_list_out
    '''Parsing JSON file to get the log fil location'''
    with open(".\\conf.json") as json_conf:
        l_configurationData = json.load(json_conf)

    g_process_log_out = l_configurationData['process_runtime_path']
    g_hash_log_out = l_configurationData['hash_runtime_path']
    g_hash_list_out = l_configurationData['hash_captured_cache']

    '''Following block of code helps instantiate the log files , get runtime process data & its Hash ID,
     store the Hash ID with time-stamp as a base cache to calculate time interval'''
    l_objthreatMonitor = theartMonitor(g_hash_list_out,g_process_log_out,g_hash_log_out)
    l_dictCacheData = l_objthreatMonitor.process()
    l_objcache = cacheMethods()
    l_objcache.store_cache(g_hash_list_out,l_dictCacheData)

    '''Following block of code inside the infinite loop ,gets runtime process data & its Hash ID. Compare the new 
    Hash ID time stamp with Base Hash ID time stamp and update the cache as needed. '''
    while True:
        l_dictCacheData = l_objthreatMonitor.process()
        l_objcache = cacheMethods()
        l_objcache.update_cache(l_dictCacheData)
        l_objthreatMonitor.display_proc_running(g_process_log_out,l_dictCacheData)

    return 0

if __name__ == '__main__':
    print('Threat Monitor Tool running...','\n','Press Ctrl+C to exit')
    try:
        main()
    except KeyboardInterrupt :
        print('\n Threat Monitoring tool exiting...','\n','Please Find Tool logs at .\\TM_tool_Logs\\')

