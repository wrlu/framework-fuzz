import logging

logging.getLogger('angr').setLevel('WARNING')
logging.getLogger('pyvex.lifting.libvex').setLevel('WARNING')

LOG_FILE = 'log.log'

file_handler = logging.FileHandler(LOG_FILE) 
console_handler = logging.StreamHandler()  
file_handler.setLevel('INFO')     
console_handler.setLevel('INFO')   

fmt = '%(asctime)s - %(levelname)8s - %(filename)20s - LINE:%(lineno)4s - %(message)s'  
formatter = logging.Formatter(fmt) 
file_handler.setFormatter(formatter) 
console_handler.setFormatter(formatter)

logger = logging.getLogger('updateSecurity')
logger.setLevel('DEBUG')     

logger.addHandler(file_handler)    
logger.addHandler(console_handler)