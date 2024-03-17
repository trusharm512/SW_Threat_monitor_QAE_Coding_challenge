import json
class filePath:

    def __init__(self):
        with open(".\\Test_file_path.json") as json_conf:
            l_configurationData = json.load(json_conf)

        self._tool_exe_path = l_configurationData['TM_tool_exe_path']
        self._tool_process_log_path = l_configurationData['TM_tool_process_log_path']
        self._tool_runtime_log_path = l_configurationData['TM_tool_hash_runtime_log_path']
        self._tool_hash_log_path = l_configurationData['TM_tool_hash_list_cache_log_path']
        self._test_results_path= l_configurationData['Test_case_result_path']
        self._test_logs_path= l_configurationData['Test_case_log_path']

    def getFilePath(self,fileName):

        if fileName=='tmToolPath':
            return self._tool_exe_path
        elif fileName == 'tmToolProcessLogPath':
            return self._tool_process_log_path
        elif fileName == 'tmToolRuntimeLogPath':
            return self._tool_runtime_log_path
        elif fileName == 'tmToolHashLogPath':
            return self._tool_hash_log_path
        elif fileName == 'testResultPath':
            return self._test_results_path
        elif fileName == 'testLogPath':
            return self._test_logs_path
