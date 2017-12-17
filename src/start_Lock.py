# coding="utf-8"

from Lock import LockServer
from defination import *

myServer = LockServer(LOCKHOST, LOCKPORT)
myServer.run()
