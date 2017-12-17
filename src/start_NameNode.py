# coding="utf-8"

from NameNode import NameNodeServer
from defination import *

myServer = NameNodeServer(NAMENODEHOST, NAMENODEPORT, '/Users/mac/Desktop/Distributed-Encrypted-File-System/DEFS/NameNode/')
myServer.run()

