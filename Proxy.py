import os
import socket
import select
import threading
import hashlib
import time
import sys
from time import sleep
import re
from concurrent.futures import ThreadPoolExecutor
class proxyServer():
	def __init__(self):
		self.host=str("127.0.0.1")
		self.port=0
		self.server=None
		self.threads=[]
		self.pool =None
	def setPort(self):
		self.port=int(sys.argv[2])
	def setHost(self):
		self.host=str(sys.argv[1])
	def createSocket(self):
		try: 
			self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.server.bind((self.host,self.port)) 
			self.server.listen(5) 
			print(str(self.host))
			print("The proxy server has started. Listening on port "+ str(self.port) +"...")
		except Exception as errors:
			if self.server:
				self.server.close() 
			print ("Could not open socket: " + errors) 
			os._exit(1) 
	def run(self):
		try:
			self.setHost()
			self.setPort()
			self.createSocket() 
			running = 1
			inputSock = [self.server]
			self.pool = ThreadPoolExecutor(max_workers=10)
			while running: 
				inputReady,outputReady,exceptReady = select.select(inputSock,[],[])
				for s in inputReady:                
					# handle the server socket 
					#c = handle(self.server.accept())
					#if a client connection is established, serve the requests in a new thread
					#c.start()
					self.pool.submit(self.startThread,self.server.accept())
					# c = self.startThread(self.server.accept())
					# self.threads.append(c)
					# for t in self.threads:
					# 	if hasattr(t, "stopped"):
					# 		t.join()
		except KeyboardInterrupt:
			print("Keyboard Interrupt")
			os._exit(1)
		except Exception as err:
			# close all threads 
			print("Closing server")
			print("Error - ", err)
			self.server.close() 
			for c in self.threads: 
				c.join()
			os._exit(1)
	def startThread(self,client):
		thread = handle(client)
		thread.start()
		return thread
class handle(threading.Thread): 
	def __init__(self, clientAddr):
		(client, address) = clientAddr
		threading.Thread.__init__(self, name = address)
		self.client = client  # client socket
		self.clientAddr = address  #client address
		self.size = 1024
		self.address = ''
		self.sock = None
		self.requestEncoding =''
		self.responseEncoding=''
		self.method =''
	def run(self):
		#receive the request from the client
		request = self.client.recv(self.size)
		self.requestEncoding = self.getEncoding(request)
		if not request:
			self.client.close()
			sys.exit()
		
		if not self.checkRequestMethod(request.decode(self.requestEncoding)):
			self.client.close()
			sys.exit()
		self.method = self.getRequestMethod(request.decode(self.requestEncoding))
		self.address = self.getRequestHost(request.decode(self.requestEncoding))	
		if self.address:
			if(self.method =='GET'):
				self.doGet(request)
			
			#elif(self.method == 'CONNECT'):
			#	self.doConnect(request)
			else:
				response = "<html><h1>Invalid Protocol</h1>" + "<body>Protocol specified is not supported/implemented</body></html>"
				response = "HTTP/1.1" + " 501 Not Implemented\r\n" + "Content-Type: text/html\r\nContent-Length: " + str(len(response)) + "\r\n\r\n" + response            
				self.client.send(response.encode())
		self.client.close()
	def printRequestInfo(self,request,fileName,info):
		
		h ,m= self.getInfo(request.decode(self.requestEncoding))
		print("------------------------------------------------\n"+\
			"request: \n"+\
			"\ttime: ",time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+"\n"+\
			"\thost: ",h+"\n"+\
			"\tmethod: ",m+"\n"+\
	  		"\tfile: ",fileName+"\n"+\
	  		"\tinfo: ",info)
	def doGet(self,request):
		
		fileName = self.getFileName(request)
		md5Name = self.getMD5(fileName)
		fileExist = self.searchCache(md5Name)
		#print(request)
		try:


			if self.redirectToPhishing(fileName):
				return

			if not fileExist:
				response = self.forwardRequest(request)	
				threading.Thread(target = self.saveCache, args=(request, response)).start()
				info ="no cache, forward this request"
				#self.printRequestInfo(request,fileName,info)
				self.client.send(response)
				#cache response for use for consequent requests
			else: 
				if self.existBrowserCache(request.decode(self.requestEncoding)):
					response = self.forwardRequest(request)
					self.responseEncoding = self.getEncoding(response)
					status = self.getResponsStatus(response.decode(self.responseEncoding))
					print("status is ",status)
					if status =='200':
						threading.Thread(target = self.saveCache, args=(request, response)).start()
					info ="exist browser cache, forward this request"
					self.printRequestInfo(request,fileName,info)
					self.client.send(response)
				else:
					date = self.getModifiedDate(md5Name)
					newRequest = self.createNewRequest(request.decode(self.requestEncoding),date)			
					response = self.forwardRequest(newRequest.encode(self.requestEncoding))
					self.responseEncoding = self.getEncoding(response)
					status = self.getResponsStatus(response.decode(self.responseEncoding))
					if status == '304':
						with open("./cache/" + md5Name, 'rb') as fh:
							response = fh.read()
							fh.close()
						info=" file is not modified, return cache"
						self.printRequestInfo(request,fileName,info)
					elif status =='404':
						info = "file is not found, forward this request"
						self.printRequestInfo(request,fileName,info)	
					elif status =='200':
						info = "file is modified, forward this request"
						self.printRequestInfo(request,fileName,info)						
						threading.Thread(target = self.saveCache, args=(request, response)).start()
					# print(response)
					self.client.send(response)			
		except socket.gaierror as err:
			response = "<html><h1>Host Not Found</h1>" + "<body>Destination Host - " + self.getHost(request.decode(self.requestEncoding)) + " cannot be reached</body></html>"
			response = "HTTP/1.1" + " 400 Bad Request\r\n" + "Content-Type: text/html\r\nConteznt-Length: " + str(len(response)) + "\r\n\r\n" + response
			self.client.send(response.encode(self.requestEncoding))
			print("Error - ", err)
		except socket.error as err:
			print("Error - ", err)
	def redirectToPhishing(self,fileName):
		redirectList = []

		with open("./redirect/redirectList.txt", 'r') as fh:
			for line in fh.readlines():
				redirectList.append(line.strip("\n"))

		print("loading redirectList:\n")
		print(redirectList)
		# print(redirectList)
		if redirectList:
			for redirectUrl in redirectList:

				if (redirectUrl in fileName):
					print("\n--------REDIRECT:BEGIN FISHING NOW---------\n")
					print("\n--[%s] "%fileName+"Phishing HIT--")
					# request=self.replaceUrlToGet("www.scu.edu.cn")
					feedbackText = ""
					with open("./redirect/text.txt", 'r') as fh:
						feedbackText = fh.read()
						feedbackText = str(feedbackText)
						fh.close()

					response = "<html><h1>You are cheated!This is a phishing website!</h1>" + "<body><font size='20px'>Destination Host - " + fileName + " is redirected by us!</font><br>" \
							   + feedbackText \
							   + "</body></html>"
					response = "HTTP/1.1" + " 200 OK\r\n" + "Content-Type: text/html\r\nConteznt-Length: " + str(
						len(response)) + "\r\n\r\n" + response
					self.client.send(response.encode(self.requestEncoding))
					return True
				else:
					return False
	
	def forwardRequest(self,request):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		address = self.address.split(":")
		if (len(address) == 1 ) :
			if(self.method =='GET'):
				address.append(80)
			elif(self.method=='CONNECT'):
				address.append(443)
		self.sock.connect((address[0], int(address[1])))
		self.sock.send(request)
		recvData = self.sock.recv(self.size)
		dataRecvd = recvData
		while recvData:
			recvData = self.sock.recv(self.size)
			dataRecvd = dataRecvd + recvData
		if self.sock:			
			self.sock.close()
		return dataRecvd

	def getInfo(self,request):
		method = request.split("\r\n")[0].split(" ")[0]
		for line in request.split("\r\n"):
			if (len(line.lower().split("host: ")) > 1):
				host = line.lower().split("host: ")[1]
				break
			host = ' '
		return host,method
	def existBrowserCache(self,request):
		for line in request.split("\r\n"):
			if (len(line.lower().split("if-modified-since: ")) > 1):
				return True
		return False
	def createNewRequest(self,request,date):
		newRequest=''
		for line in request.split("\r\n"):
			if (len(line.lower().split("if-modified-since: ")) > 1):
				return request
		data =request.split("\r\n\r\n")
		str="\r\nIf-Modified-Since: "+date
		newRequest =data[0]+str+"\r\n\r\n"
		return newRequest

	def getResponsStatus(self,request):
		requestLine = request.split("\n")[0]
		status = requestLine.split(" ")[1]
		return status

	def getModifiedDate(self,fileName):
		fileName = "./cache/" + fileName
		date = os.path.getmtime(fileName)
		date = time.localtime(date) 
		modifiedDate= time.strftime('%a, %d %b %Y %H:%M:%S',date)
		return modifiedDate+" GMT"

	def getRequestMethod(self,request):
		method = request.split("\n")[0].split(' ')[0]
		return method

	#check the method if get or connect
	def checkRequestMethod(self,request):
		if('GET' in request.split("\n")[0].split(' ')):
			return True
		elif('CONNECT' in request.split('\n')[0].split(' ')):
			return True
		return False

	def getRequestHost(self, data):
		for line in data.split("\r\n"):
			if (len(line.lower().split("host: ")) > 1):
				return line.lower().split("host: ")[1]
		return ''

	def getFileName(self,request):
		requestLine =request.decode().split("\n")[0];#get the request line ,eg:GET http://sina.com/ HTTP/1.1
		name = requestLine.split(" ")[1]
		if (len(name.split('//')) > 1): #remove http,get the name
			name = name.split('//')[1]
		if(name[-1]=='/'):
			name=name[:-1]
		address = name.split(":")
		if (len(address) == 1 ) :
			name = name + ":80"
		return name
	def getMD5(self,name):
		md5 =hashlib.md5()
		md5.update(name.encode())
		md5 =md5.hexdigest()
		return md5
	def searchCache(self,md5Name):
		md5Name = "./cache/" + md5Name
		#Check if the file exists in the cache
		if (os.path.exists(md5Name)):
			#if the file exists in the cache then check if the cached file was older than the Cache timeout value
			return True
		else:
			return False
	def saveCache(self,request,data):
		fileName = self.getFileName(request)
		md5Name =self.getMD5(fileName)
		if not os.path.exists("./cache"):
			os.mkdir("./cache")
		try:
			with open("./cache/" + md5Name, 'wb') as fh:
				fh.write(data)
				fh.close()
			sys.exit()
		except Exception as err:
			print("Error - ", err)
		sys.exit()
	def decodeOptions(self):
		options = ['ascii', 'big5', 'big5hkscs', 'cp037', 'cp273', 'cp424', 'cp437', 'cp500', 'cp720', 'cp737', 'cp775', 'cp850', \
					'cp852', 'cp855', 'cp856', 'cp857', 'cp858', 'cp860', 'cp861', 'cp862', 'cp863', 'cp864', 'cp865', 'cp866', \
					'cp869', 'cp874', 'cp875', 'cp932', 'cp949', 'cp950', 'cp1006', 'cp1026', 'cp1125', 'cp1140', 'cp1250', 'cp1251',\
					'cp1252', 'cp1253', 'cp1254', 'cp1255', 'cp1256', 'cp1257', 'cp1258', 'cp65001', 'euc_jp', 'euc_jis_2004', 'euc_jisx0213', \
					'euc_kr', 'gb2312', 'gbk', 'gb18030', 'hz', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', \
					'iso2022_jp_ext', 'iso2022_kr', 'latin_1', 'iso8859_2', 'iso8859_3', 'iso8859_4', 'iso8859_5', 'iso8859_6', 'iso8859_7', \
					'iso8859_8', 'iso8859_9', 'iso8859_10', 'iso8859_11', 'iso8859_13', 'iso8859_14', 'iso8859_15', 'iso8859_16', 'johab', \
					'koi8_r', 'koi8_t', 'koi8_u', 'kz1048', 'mac_cyrillic', 'mac_greek', 'mac_iceland', 'mac_latin2', 'mac_roman', 'mac_turkish', \
					'ptcp154', 'shift_jis', 'shift_jis_2004', 'shift_jisx0213', 'utf_32', 'utf_32_be', 'utf_32_le', 'utf_16', 'utf_16_be', \
					'utf_16_le', 'utf_7', 'utf_8', 'utf_8_sig' ]
		return options
	def getEncoding(self,data):
		for encoding in self.decodeOptions():
			try:
				data = data.decode(encoding)		
			except:
				pass
			else:
				return encoding

def checkSysArgs():
	
	if len(sys.argv) <=2:
		print("Usage - mProxy.py [Host] [Port] [cache size]")    
		os._exit(1)
	
	if (len(sys.argv) > 2):
		try:
			str(sys.argv[1])
		except:
			print("Specify the host value as a String")
			print("Usage - mProxy.py [Host] [Port] [cache size]")             
			os._exit(1)
		try:
			int(sys.argv[2])
		except:
			print("Specify the port value as a Integer number")
			print("Usage - mProxy.py [Host] [Port] [cache size]")           
			os._exit(1)
		try:
			float(sys.argv[3])
		except:
			print("Specify the cache size value as a Float number")
			print("Usage - mProxy.py [Host] [Port] [cache size]")           
			os._exit(1)
def manageCache(size):
	size =float(size)
	fileDict={}
	path=""
	while True:
		if getDirSize("./cache")>size:
			print("info:\n\tToo many caches ,staring cleaning ....")
			for root,dirs,files in os.walk("./cache"):
				path =root
				for file in files:
					date = os.path.getmtime(os.path.join(root,file))
					fileDict[file]=date
			temp = sorted(fileDict.items(),key = lambda item:item[1])
			for i in range(int(len(temp)/2)):
				try:
					os.remove(os.path.join(path,temp[i][0]))
				except Exception as err:
					print(err)

			print(getDirSize("./cache"))
		sleep(600)
def getDirSize(path):
	size = 0
	for root,dirs,files in os.walk(path):
		for file in files:
			size +=os.path.getsize(os.path.join(root,file))
	size = size/1048576
	return size
if __name__ == "__main__":
	checkSysArgs()
	threading.Thread(target = manageCache,args=(sys.argv[3])).start()
	s = proxyServer()
	s.run()
