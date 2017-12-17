# coding="utf-8"

from DataNode import DataNodeServer
from defination import *

myServer = DataNodeServer(DATANODEHOST, DataNode_5, '/Users/mac/Desktop/Distributed-Encrypted-File-System/DEFS/DataNode/7005/')
myServer.run()