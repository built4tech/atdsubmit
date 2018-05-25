import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import Queue
import threading
import sys
import hashlib


import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

from atd import atd

ATD_Server = "192.168.20.140"
ATD_User = "apiuser"
ATD_Pass = "McAfee123!"

q = Queue.Queue()
threads = []

last_time = time.time()

NUM_WORKER_THREADS = 1
HEARTBEAT_VALUE = 300 # heartbeat of 5 minutes
MONITORED_FOLDER = u"c:\\Users\\cmunoz\\eclipse-workspace\\python-workspace\\oberver_test\\pruebas"
files_uploaded = []
logFile=os.curdir + os.sep + 'log' + os.sep + 'observer.log'
logger = ""

class sandbox(atd.atd):
    pass
    

class Utils():
    MAX_FILE_SIZE = 120
    SIZE_CONSTANT  = 1024
    
    @classmethod
    def check_size(self, size_in_bytes):
        FILE_UPLOAD_FLAG = True
        
        if size_in_bytes > self.SIZE_CONSTANT:
            size_in_kb = size_in_bytes / self.SIZE_CONSTANT
            if size_in_kb > self.SIZE_CONSTANT:
                size_in_mb = size_in_kb /self.SIZE_CONSTANT
                if size_in_mb > self.MAX_FILE_SIZE:
                    FILE_UPLOAD_FLAG = False
        
        if FILE_UPLOAD_FLAG:
            return True
        else:
            return False  
        
    @classmethod
    def md5Checksum(self, filename):
        with open(filename, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
                
            return m.hexdigest()

        
    @classmethod  
    def isFileExctractionCompleted(self, samplePath):
        if os.path.exists(samplePath):
            statinfo = os.stat(samplePath)
            
            sampleModTime = statinfo.st_mtime
            currentSystemTime = time.time()
    
            accessTime = currentSystemTime - sampleModTime
            
            if accessTime < 1:
                ''' Need to skip the sample file as its incomplete and being exctracted|downloaded from network interface '''
                FILE_COMPLETE = False
            else:
                ''' No need to skip the sample, sample file is complete and can be used for submission '''
                FILE_COMPLETE = True
    
            return(FILE_COMPLETE)
        
    @classmethod
    def scan_dir_for_samples(self, path):
       
        if not os.listdir(path):
            # folder empty nothing must be done
            return []
        
        # La siguiente rutina solo se ejecuta una vez ya que nada mas entrar en el bucle
        # sale con el break, asi conseguimos que os.walk no haga un recorrido en profundidad
        # y se quede en el primer nivel, filenames incluira todos los ficheros existentes
        for (dirpath, dirnames, filenames) in os.walk(path):
            break
        
        return filenames
    
    @classmethod
    def log_setup(self):
        ''' Setting up the logger '''
        global logger    
     
    
        logger = logging.getLogger('myapp')
    
        logFolder = os.curdir + os.sep + 'log'
        if not os.path.exists(logFolder):
            os.makedirs(logFolder)
    
        '''
            Rotating log file with size of 5Mb.
        '''
        hdlr = RotatingFileHandler(logFile, mode='a', maxBytes=(4*1000*1000), backupCount=10, encoding=None, delay=0)
    
        '''
            Value        Type of interval
            's'            Seconds
            'm'            Minutes
            'h'            Hours
            'd'            Days
            'w0'-'w6'    Weekday (0=Monday)
            'midnight'    Roll over at midnight
    
            will rotate logs 3 days once
        
        hdlr = TimedRotatingFileHandler(logFile, when="d", interval=3, backupCount=100, encoding=None, delay=0) 
        '''
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
        logger.setLevel(logging.INFO)
    
        return (0)
                
class Handler(FileSystemEventHandler):
    
    
    def on_any_event(self, event):
        global last_time
        global files_uploaded
        
        if event.is_directory:
            return None

        elif event.event_type == 'created':
            logger.info ('Created Event detected, %s' % (event.src_path))
            
            if not os.path.exists(event.src_path):
                return

            statinfo = os.stat(event.src_path)
              
            if Utils.isFileExctractionCompleted(event.src_path) and Utils.check_size(statinfo.st_size):
                # Utils.isFileExctractionCompleted comprueba que el fichero se haya coipado completamente en la carpeta
                # Utils.check_size coprueba que el fichero se encuentra en los limites de tamano maximo establecido
                last_time = time.time()
                files_uploaded.append(os.path.basename(event.src_path))
                q.put(event.src_path)
                
            else:
                logger.info('File no yet downloaded or beyond limits, %s' %(event.src_path))
  
  
        

class Watcher():
    def __init__(self):
        self.observer=Observer()
        
    def runner(self, path_to_watch, mySandbox):
        global last_time
        global files_uploaded
        
        event_handler = Handler()
        
        self.observer.schedule(event_handler, path_to_watch, recursive=False)
        self.observer.start()
        
        try:
            while True:
                time.sleep(1)
                current_time = time.time()
                if current_time - last_time > HEARTBEAT_VALUE:
                    # Si pasan 5 minutos sin detectar ningun archivo nuevo monitorizamos la carpeta por si hay 
                    # alguno que no se haya podido subir por estar copiandose y desencadenamos un heartbeat
                    # para mantener la conexion abierta
                    conn, conn_info= mySandbox.heartbeat()
                    
                    if conn:
                        last_time = time.time()
                        logger.info('Heartbeat received from  %s ' %(ATD_Server))
                    else:
                        logger.error('Heartbeat not received from %s ' %(ATD_Server))
                        logger.error(conn_info)
                        raise KeyboardInterrupt
                        
                    files = Utils.scan_dir_for_samples(MONITORED_FOLDER)
                    for file_name in files:
                        # Aqui anadimos las acciones a monitorizar, por ejemplo que el archivo no se haya subido
                        # previamente, que este completamente descargado y que el tamano este entre los limites
                        # una vez hecho subiremos el archivo a la cola para que sea gestionado
                        if not file_name in files_uploaded:
                            file_full_path = MONITORED_FOLDER + os.sep + file_name
                            
                            if os.path.exists(file_full_path):

                                statinfo = os.stat(file_full_path)
               
                                if Utils.isFileExctractionCompleted(file_full_path) & Utils.check_size(statinfo.st_size):
                                    last_time = time.time()
                                    files_uploaded.append(os.path.basename(file_full_path))
                                    q.put(file_full_path)
                
        except KeyboardInterrupt:
            logger.info('Keyboard interrupt received. Stopping observer')
            self.observer.stop()
        
        self.observer.join()

def manage_uploads(i, mySandbox):
    while True:
        item = q.get()
        if item is None:
            break
        
        md5 = Utils.md5Checksum(item)
        conn, value = mySandbox.isBlackorWhiteListed(md5)
        
        if conn == 1 and value == '0':
            logger.info("Submitting File %s with MD5 %s"%(item,md5))
            upload_conn, upload_value = mySandbox.upload(item)
            if upload_conn == 1:
                logger.info("File %s submitted successfully"%item)
            else:
                logger.info("Error submitting file \t %s"%upload_value)
        else:
            logger.info("File %s with MD5 %s already white or black listed"%(item,md5))
                    
        q.task_done()
        

def main():
    global files_uploaded
    
    # Inicializando logger
    Utils.log_setup()
    logger.info('Logger initialized')
    
    # Conectando con solucion Sandbox
    mySandbox = sandbox(ATD_Server)
    conn, conn_info = mySandbox.connect(ATD_User, ATD_Pass)
    
    if conn:
        logger.info('Connection to Sandbox appliance %s sucessfull' %(ATD_Server))
    else:
        logger.error('Connection to Sandbox appliance: %s unsucesfull' %(ATD_Server))
        logger.error(conn_info)
        sys.exit()
            
    # Analizando ruta origen para ignorar archivos preexistentes
    for eachFile in Utils.scan_dir_for_samples(MONITORED_FOLDER):
        logger.info('File already in folder, %s' %(eachFile))
        files_uploaded.append(eachFile)
    
    # Inicializando hilos para gestionar los uploads a la plataforma ATD
    for i in range(NUM_WORKER_THREADS):
        t = threading.Thread(target=manage_uploads, args=(i, mySandbox))
        threads.append(t)
        t.setDaemon(True)
        t.start()

    
    # Iniciando proceso de monitorizacion de eventos
    w = Watcher()
    w.runner(MONITORED_FOLDER, mySandbox)
    
    # Desconectando solucion Sandbox
    conn, conn_info = mySandbox.disconnect()
    
    if conn:
        logger.info('Disconection from Sandbox appliance %s sucessfull' %(ATD_Server))
    else:
        logger.error('Disconnection from Sandbox appliance: %s unsucesfull' %(ATD_Server))
        logger.error(conn_info)
        
    # Matando hilos creados para upload a ATD
    logger.info('Stopping threads')
    for i in range(NUM_WORKER_THREADS):
        q.put(None)        
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
    

