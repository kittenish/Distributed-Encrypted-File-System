import sys
reload(sys)
sys.setdefaultencoding('utf8')

UPLOAD = (0)
DOWNLOAD = (3)
WRITE = (1)
READ = (2)
DELETE = (4)
DATANODE = (5)
READ_LOCK = (6)
READ_RELEASE = (7)
WRITE_LOCK = (8)
WRITE_RELEASE = (9)
NAMENODEHOST = ('127.0.0.1')
NAMENODEPORT = (5000)
DATANODEHOST = ('127.0.0.1')
DataNode_1 = (7001)
DataNode_2 = (7002)
DataNode_3 = (7003)
DataNode_4 = (7004)
DataNode_5 = (7005)
LOCKHOST = ('127.0.0.1')
LOCKPORT = (9090)
TEMP_PLACE = ('/Users/mac/Desktop/')
TEMP_PLACE_ = ('/Users/mac/Desktop')