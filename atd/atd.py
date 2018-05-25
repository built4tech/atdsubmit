#!/usr/bin/python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:        atd
# Purpose:     Use of the ATD API 
#
# Author:      Carlos Munoz (charly.munoz@gmail.com)
#
# Created:     15/05/2015
# Copyright:   (c) Carlos M 2015
#-------------------------------------------------------------------------------
#
#-------------------------------------------------------------------------------
# Version: V.0.1.5
#-------------------------------------------------------------------------------

import requests
import json
import os

try:
	requests.packages.urllib3.disable_warnings() # Disable warnings on the console when the certification validation is ignored.
except:
	pass # python version previous to 2.7.9

class atd():

	def __init__(self,atdserver):
		'''
		Description: Constructor
		Input:       IP address of ATD Server
		Output:      No Output
		'''
		self.atdserver   = atdserver
		self.session	 = ''
		self.userId      = ''
		self.matdVersion = ''
		self.apiVersion  = ''

		self.sessionhdr = {}
		
	def connect(self, user, password):
		'''
		Description: Connection method, stablish a connection to the ATD server and populates all 
			     self variables of the constructor
		Input:       User and password
		Output:      Two possible values: 
			     (0, error_info): Unsucessful connection, error_info contain the cause of the error
			     (1, 'Connection sucessful): Sucessful connection
		'''
		authheader = {
				'Accept': 'application/vnd.ve.v1.0+json',
				'Content-Type': 'application/json',
				'VE-SDK-API': '%s'%self.b64(user,password)
			     }

		url = 'https://%s/php/session.php'%self.atdserver

		try:
			r = requests.get(url, headers = authheader, verify=False)	
		except Exception as e:
			error_info = 'Error connecting to ATD:\n %s'%e
			return (0, error_info)

		if r.status_code == 200:
			server_info = json.loads(r.content)
			if server_info['success'] == True:
				self.session     = server_info['results']['session']
				self.userId      = server_info['results']['userId']
				self.matdVersion = server_info['results']['matdVersion']
				self.apiVersion  = server_info['results']['apiVersion']
				self.sessionhdr  = {
				  'Accept': 'application/vnd.ve.v1.0+json',
				  'Content-Type': 'application/json',
				  'VE-SDK-API': '%s'%self.b64(self.session, self.userId)
			                       }
			else:
				error_info = 'Connection unsucessful'
				return (0, error_info)
		else:
			error_info = 'Error conecting to ATD, Status Code: %d'%r.status_code
			return(0, error_info)
		
		return(1, 'Connection sucessful')
		
	def disconnect(self):
		'''
		Description: Disconnection method.
		Input:       No input
		Output:      Two possible values: 
			     (0, error_info): Unsucessful disconnection, error_info contain the cause of the error
			     (1, 'Disconnection sucessful): Sucessful disconnection
		'''	
		url = 'https://%s/php/session.php'%self.atdserver
		
		try:
			r = requests.delete(url, headers = self.sessionhdr, verify=False)
		except Exception as e:
			error_info = 'Error disconnecting from ATD:\n %s'%e
			return (0, error_info)
		if r.status_code == 200:
			server_info = json.loads(r.content)

			if server_info['success'] == True:
				return(1,'Disconnection successful')
			else:
				error_info = 'Error disconecting from ATD - Check credentials or content type header'
				return(0, error_info)
		else:
			error_info = 'Error disconnection from ATD, Status Code: %d'%r.status_code
			return(0, error_info)

	def heartbeat(self):
		'''
		Description: Hearbeat value
		Input:       No input
		Output:      Two possible values: 
			     (0, error_info): Error getting heartbeat value
			     (1, heartbeat_value): Heartbeat value
		'''	
		url = 'https://%s/php/heartbeat.php'%self.atdserver

		try:
			r = requests.get(url, headers = self.sessionhdr, verify=False)
		except Exception as e:
			error_info = 'Error getting heartbeat:\n%s'%e
			return(0, error_info)

		if r.status_code == 200:
			server_info = json.loads(r.content)

			if server_info['success'] == True:
				return (1, server_info['results']['heartBeat'])

			else:
				error_info = 'Error getting heartbeat, check credentials or content type header'
				return (0, error_info)
		else:
			error_info = 'Error getting heartbeat, status code: %d'%r.status_code
			return (0, error_info)

	def force_decode(self, string, codecs=['utf8', 'cp1252','ascii']):
		'''
		Description: Internal function that receives a string and try to decode it using different codecs
		Input:       
			     string: String to decode
			     codecs: List of possible codecs

		Output:      Two possible values: 

			     (0, 'codecs not valid'): The funciton is not able to find the coded used to coded the string
			     (1, string_decoded): Tuple with a positive value and the decoded string
		'''
		for i in codecs:
			try:
				return (1, string.decode(i))
			except:
				pass
		return (0, 'codecs not valid')

	def upload_file(self, filetosubmit, vmProfileList=None):
		'''
		Description: Regular upload procedure, uploads a file to the ATD server for inspection
		Input:       
				 submitType:    SubmitType indicate the type of upload:
				 	* 0 - Regular File Upload
				 	* 1 - URL Submission
				 	* 2 - Submit file and URL (Both things)
				 	* 3 - URL Download, File is firstly downloaded and the analyzed
				 				In this prodedure SubmitType is always 0

			     filetosubmit:  Path to the file to be submitted
			     vmProfileList: ATD Profile ID for inspection
			     numVMProfiles: Value not used in this version (3.60.XX)
 			     overrideOS:    Value not used in this version (3.60.XX)

		Output:      Two possible values: 

			     (0, error_info): Unsucessful procedure
			     (1, {'jobID':'xxx','taskId':'xxx','file':'xxx','md5':'xxx','size':'xxx':'mimeType':'xxx'}): Sucessful upload

			     Note: If the returned taskId is -1 the submitted file is a zip file use the jobId and the procedure taskIdList to get 
			     taskId for each file related to the jobId submition
		'''
		xMode         = 0
		numVmProfiles = 1
		overrideOS    = 1
		submitType    = 0
		messageId	  = ""
		url 		  = ""

		url = 'https://%s/php/fileupload.php'%self.atdserver

		if vmProfileList:
			postdata = {'data':'{"data":{"xMode": "%d", "overrideOS": "%d", "messageId": "%s", "vmProfileList":"%s","submitType":"%d", "url":"%s"}}'%(xMode, overrideOS, messageId, vmProfileList, submitType, url)}
		else:
			postdata = {'data':'{"data":{"xMode": "%d", "overrideOS": "%d", "messageId": "%s", "submitType":"%d", "url":"%s"}}'%(xMode, overrideOS, messageId, submitType, url)}

		value, data = self.force_decode(self.get_filename(filetosubmit)) # This call returns an unicode (not coded) string for further manipulation
		
		if value:
			datatosubmit = data.encode('ascii','replace') # This function replace non ascci characters used on the name of the file
		else:
			datatosubmit = data

		try:
			files = {'amas_filename': (datatosubmit, open(filetosubmit, 'rb'))}
		except Exception as e:
			error_info = 'Upload method: Error opening file: %s'%e
			return(0, error_info)			

		custom_header = {
			 'Accept': 'application/vnd.ve.v1.0+json',
			 'VE-SDK-API': '%s'%self.b64(self.session, self.userId)
			 }
		
		try:
			r = requests.post(url, postdata, headers = custom_header, files=files, verify=False)

		except Exception as e:
			error_info = 'Error submitting file to ATD:\n%s'%e
			return(0, error_info)

		if r.status_code == 200:
			server_info = json.loads(r.content)
			if server_info['success'] == True:	
				info = {
					'jobId'         : server_info['subId'],
					'estimatedTime' : server_info['estimatedTime'],
					'taskId'        : server_info['results'][0]['taskId'],
					'file'          : server_info['results'][0]['file'],
					'md5'           : server_info['results'][0]['md5'],
					'size'          : server_info['results'][0]['size'],
					'mimeType'      : server_info['mimeType']
					}
				return (1,info)	
			else:
				error_info = 'Upload operation did not return a success value'
				return (0,error_info)
		else:
			error_info = 'Error uploading file, bad credentials or header - status code: %d'%r.status_code
			return (0, error_info)
	
	
	def upload(self, filetosubmit, vmProfileList=0):
		'''
		This method does the same as upload_file but is more updated, taken from atd bro submitter
		'''
		''' 
		    From bro-atdsubmitter
		    messageId : "99bb88rr11oo00" is a constant string used to define type of submission 
		    # Note : do not change the string i.e. messageId 
		'''

		messageId = ""
		source_IP = ""
		analyzer_profile_id = vmProfileList

		url = 'https://%s/php/fileupload.php'%self.atdserver
		
		custom_header = {
		     'Accept': 'application/vnd.ve.v1.0+json',
		     'VE-SDK-API': '%s'%self.b64(self.session, self.userId)
		     }

		postdata = {'data':'{"data":{"xMode":0,"skipTaskId":1, "srcIp":\"'+str(source_IP)+'\","destIp":"","messageId":\"'+str(messageId)+'\","analyzeAgain":1,"vmProfileList":'+str(analyzer_profile_id)+'},"filePriorityQ":"run_now"}'}
		
		
		
		
		try:
			file_data_up = open(filetosubmit, 'rb').read()
		
			#file_up = {'amas filename': [unicode(os.path.basename(filetosubmit), errors='ignore'), file_data_up]}
			
			# Las commented line is replaced by this code
			# ******************************************
			value, data = self.force_decode(self.get_filename(filetosubmit))
			
			if value:
				datatosubmit = data.encode('ascii','replace') # This function replace non ascci characters used on the name of the file
			else:
				datatosubmit = data
			
			file_up = {'amas filename': [datatosubmit, file_data_up]}
			# ******************************************
		except Exception as e:
			error_info = 'Upload method: Error opening file: %s'%e
			return(0, error_info)

		try:
			r = requests.post(url,postdata,files=file_up,headers=custom_header,verify=False)
		except Exception as e:
			error_info = 'Error submitting file to ATD:\n%s'%e
			return(0, error_info)


		if r.status_code == 200:
			server_info = json.loads(r.content)
			if server_info['success'] == True:    
				info = {
				    'jobId'         : server_info['subId'],
				    'estimatedTime' : server_info['estimatedTime'],
				    'taskId'        : server_info['results'][0]['taskId'],
				    'file'          : server_info['results'][0]['file'],
				    'md5'           : server_info['results'][0]['md5'],
				    'size'          : server_info['results'][0]['size'],
				    'mimeType'      : server_info['mimeType']
				    }
				return (1,info)    
			else:
				error_info = 'Upload operation did not return a success value'
				return (0,error_info)
		else:
			error_info = 'Error uploading file, bad credentials or header - status code: %d'%r.status_code
			return (0, error_info)


	def taskIdList(self, jobId):
		'''
		Description: List of Task IDs
		Input:       jobId
		Output:      Two possible values: 
			     (0, error_info): Error getting the list of Task IDs
			     (1, list_of_task_iDs): 
		'''	
		# If the uploaded file is a zip file (taskId -1), it might contain multiple files to be analyzed
		# the whole submition has a unique jobId but each file inside has its own taskId
		# This procedure gets the complete list so later on allows to query the status of 
		# each takid

		url = 'https://%s/php/getTaskIdList.php'%self.atdserver

		payload = {'jobId':jobId}

		try:
			r = requests.get(url, params = payload, headers = self.sessionhdr, verify=False)
		except Exception as e:
			error_info = 'Error getting list of Task IDs:\n%s'%e
			return(0, error_info)

		if r.status_code == 200:
			server_info = json.loads(r.content)

			if server_info['success'] == True:
				if len(server_info['result']):
					return (1, server_info['result']['taskIdList'].split(','))
				else:
					return (1,[])

			else:
				error_info = 'Error getting Task IDs, check credentials or content type header'
				return (0, error_info)
		else:
			error_info = 'Error getting Task IDs, status code: %d'%r.status_code
			return (0, error_info)


	def check_status(self, Id, idType='jobId'):
		'''
		Description: Check the status of the uploded file to the ATD server for inspection
		Input:       
			     Id:     ID of the task identifying the inspection operation
			     idType: idType can be taskId or jobId
		Output:      Possible values: 

				if idType = taskId

			     (0, error_info): Unsucessful procedure
			     (4, 'Sample waiting to be analyzed')
			     (3, 'Sample being analyzed')
			     (-1, 'Analysis failed')

			     (1, {'jobid': 'xxx', 'taskid':'xxx', 'filename':'xxx', 'md5':'xxx','submitTime': 'xxx',
			     'vmProfile':'xxx','vmName':'xxx','vmDesc':'xxx','summaryFiles':'xxx', 'useLogs':'xxx',
			     'asmListing':'xxx','PEInfo':'xxx', 'family':'xxx'})
	
			     (2, {'jobid': 'xxx', 'taskid':'xxx', 'filename':'xxx', 'md5':'xxx','submitTime': 'xxx',
			     'vmProfile':'xxx','vmName':'xxx','vmDesc':'xxx','summaryFiles':'xxx', 'useLogs':'xxx',
			     'asmListing':'xxx','PEInfo':'xxx', 'family':'xxx'})

			    if idType = jobId

			     (0, error_info): Unsucessfull procedure
			     (-1, 'Analysis failed')
			     (2, 'Sample waiting to be analyzed')
			     (3, 'Sample being analyzed')

			     Note: When a jobId of a zip file is passed as parameter then the status value inthe json
			     is the minimum value of status of individual smaples in the zip file

			     (5, {'severity': xx})

			     
		'''
		url = 'https://%s/php/samplestatus.php'%self.atdserver

		if idType != 'jobId':
			payload = {'iTaskId': Id}
		else:
			payload = {'jobId': Id}


		try:
			r = requests.get(url, params=payload, headers=self.sessionhdr, verify=False)
		except Exception as e:
			error_info = 'Can not get status of %s: %d,\nReturned error: %s '%(idType, taskId,e) 
			return (0, error_info)

		if r.status_code == 200:
			server_info = json.loads(r.content)

			if server_info['success'] == True:
				if idType != 'jobId':
					status = server_info['results']['istate']

					if status == 4: # Sample waiting in the queue to be analyzed
						return (4, 'Sample is waiting to be analyzed')
					elif status == 3: # Sample being analyzed
						return (3, 'Sample is being analyzed')
					elif status == -1: # Sample failed to be analyzed
						return (-1, 'Analysis failed')
					elif status == 1 or status == 2: # Sample correctly analyzed
						info = {
							'jobid'        : server_info['results']['jobid'],
							'taskid'       : server_info['results']['taskid'],
							'filename'     : server_info['results']['filename'],
							'md5'          : server_info['results']['md5'],
							'submitTime'   : server_info['results']['submitTime'],
							'vmProfile'    : server_info['results']['vmProfile'],
							'vmName'       : server_info['results']['vmName'],
							'vmDesc'       : server_info['results']['vmDesc'],
							'summaryFiles' : server_info['results']['summaryFiles'],
							'useLogs'      : server_info['results']['useLogs'],
							'asmListing'   : server_info['results']['asmListing'],
							'PEInfo'       : server_info['results']['PEInfo'],
							'family'       : server_info['results']['family']
						       }
						return (status, info)
					else:
						error_info = 'Unknown error checking status of taskId: %d'%taskId	
						return (0, error_info)
				else:
					status = server_info['status']

					if status == 2: # JobId waiting in the queue to be analyzed
						return (2, 'jobId is waiting for being analyzed')
					elif status == 3: # JobId being analyzed
						return (3, 'jobId is being analyzed')
					elif status == -1: # JobId failed to be analyzed
						return (-1, 'Analysis failed')
					elif status == 5: # JobId correctly analyzed
						info = {'severity': server_info['severity']}
						return (status, info)
					else:
						error_info = 'Unknown error checking status of jobId: %d'%jobId	
						return (0, error_info)

			else:
				print server_info # Debug creo que si se sube un zip y el fichero interior esta en blacklist devulevo False si es asi se deberia
							      # monitorizar para devolver otro valor indicando que el archivo contenido en el zip esta en black o whitelist
				error_info = 'Check status operation did not return a success value'
				return (0, error_info)
		else:
			error_info = 'Error checking status, bad credentials or header - status code: %d'%r.status_code
			return (0, error_info)

	def get_report(self, jobId):
		'''
		Description: Get the final result of the inspection of the sample submitted
		Input:       jobId, identification of the job
		Output:      Possible values: 

			     (0, error_info): Unsucessful procedure
			     (2, 'Result is not ready')
			     (3, 'Report not found, Ex. file not supported')
			     (1, {}): The dic includes all the json report
		'''
	
		url = 'https://%s/php/showreport.php'%self.atdserver

		payload = {'jobId':jobId, 'iType':'json'}

		custom_header = {
			        'Accept': 'application/vnd.ve.v1.0+json',
			        'VE-SDK-API': '%s'%self.b64(self.session, self.userId)
			        }
	
		try:
			r = requests.get(url, params=payload, headers=custom_header, verify=False)
		except Exception as e:
			error_info = 'Can not get report of jobId: %d,\nReturned error: %s '%(jobId,e) 
			return (0, error_info)

		if r.status_code == 400:
			info = 'Inspection not yet finished'
			return(2, info)

		if r.content.split('\n')[0] == 'Result is not ready':
			info = 'Result is not ready'
			return (2, info)
		else:
			if 'report file not found' in r.content.lower():
				server_info = 'Report not found - Ex. file not supported'
				return (3, server_info)
			else:
				server_info = json.loads(r.content)
				return (1, server_info)

	def isBlackorWhiteListed(self, md5):
		'''
		Description: This procedure returns if the file is is Whitelisted or Blacklisted
		Input:       md5
		Output:      Possible values: 

			     (0, error_info): Unsucessful procedure
			     (1, 'w')         File Whitelisted
			     (1, 'b')		  File Blacklisted
			     (1, '0')         File not White nor Black
			     (1, 'Invalid input data')
		'''
		md5 = md5.upper()
		url = 'https://%s/php/atdHashLookup.php'%self.atdserver

		custom_header = {
			 'Accept': 'application/vnd.ve.v1.0+json',
			 'VE-SDK-API': '%s'%self.b64(self.session, self.userId)
			 }

		postdata = {'data': '{"md5":"%s"}'%md5}
		
		try:
			r = requests.post(url, postdata, headers = custom_header, verify=False)
		except Exception as e:
			error_info = 'Error getting whitelisting or blacklisting info:\n%s'%e
			return(0, error_info)

		if r.status_code == 200:
			server_info = json.loads(r.content)

			if server_info['success'] == True:
				return (1, server_info['results'][md5])

			else:
				error_info = 'Error getting whitelisting or blacklisting info, check credentials or content type header'
				return (0, error_info)
		else:
			error_info = 'Error getting whitelisting or blacklisting, status code: %d'%r.status_code
			return (0, error_info)

	def b64(self, user, password):
		'''
		Description: Internal procedure to get the base64 values used for authentication
		Input:       user and password
		Output:      base64('user:pass'): The dic includes all the json report
		'''
		import base64
		auth_string = user + ':' + password
		return base64.b64encode(auth_string)

	def get_filename(self, filetosubmit):
		'''
		Description: Internal procedure to get the clean filename
		Input:       path to file
		Output:      clean filename
		'''
	
		if filetosubmit.find('/') != -1:
			file = filetosubmit.split('/')[-1]
		else:
			if filetosubmit.find('\\') != -1:
				file = filetosubmit.split('\\')[-1]
			else:
				file = filetosubmit
		return file	

