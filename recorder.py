import thread
import zlib
import hashlib
import difflib
import time
import socket
import cPickle
import random
import string
import os
import datetime
import sys
import time
global counter, data_folder
counter = 0 
data_folder = 'data/'


def save_obj(http_obj):
	global counter, data_folder
	counter += 1
	print counter
	print 'Storing ...', counter
	data = cPickle.dump(http_obj, open(data_folder+str(counter)+'.p', 'wb'))
	

	
class HTTPObject:
	def __init__(self, headers, url, content, status, reason, request_ver, webpage, rtt ):
		self.request_ver = request_ver
		self.headers = headers
		self.url = url
		self.content = content
		self.status = status
		self.reason = reason
		self.webpage = webpage
		self.maxAge = 0
		self.hash = hashlib.sha224(self.content).hexdigest()
		self.rtt = rtt


