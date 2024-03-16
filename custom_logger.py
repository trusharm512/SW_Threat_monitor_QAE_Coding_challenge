import logging, inspect

class CLogger:
    def my_logger(self,fname,msg,M,level=logging.DEBUG):
        # Set class/method name as logger name from where its called
        logger_name = inspect.stack()[1][3]
        # Create logger & set Log Level
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)
        # Create console handler or file handler
        fh = logging.FileHandler(fname,mode=M)
        # Create Formatter
        FORMAT='%(asctime)s - %(name)s - %(levelname)s - Line(%(lineno)d) : %(message)s'
        Formatter = logging.Formatter(FORMAT,datefmt="%a, %d %b %Y %H:%M:%S %p")
        #add formatter to the conole/file handler
        fh.setFormatter(Formatter)
        #add console/file handler to logger
        logger.addHandler(fh)
        #log messages
        if level == logging.CRITICAL:
            logger.critical(msg)
        elif level == logging.ERROR:
            logger.error(msg)
        elif level == logging.WARNING:
            logger.warning(msg)
        elif level == logging.INFO:
            logger.info(msg)
        elif level==logging.DEBUG:
            logger.debug(msg)

        return logger

if __name__ == '__main__':
    ld = CLogger()
    ld.my_logger('mylogs.log','messge','w',logging.INFO)
