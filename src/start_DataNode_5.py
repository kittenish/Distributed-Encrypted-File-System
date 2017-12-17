# coding="utf-8"

from DataNode import DataNodeServer
from defination import *

myServer = DataNodeServer(NAMENODEHOST, DataNode_5, '/Users/mac/Desktop/Distributed-Encrypted-File-System/DEFS/DataNode/7005/')
myServer.run()