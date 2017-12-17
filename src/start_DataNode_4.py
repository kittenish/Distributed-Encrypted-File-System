# coding="utf-8"

from DataNode import DataNodeServer
from defination import *

myServer = DataNodeServer(DATANODEHOST, DataNode_4, '/Users/mac/Desktop/Distributed-Encrypted-File-System/DEFS/DataNode/7004/')
myServer.run()