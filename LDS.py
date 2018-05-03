#!/usr/bin/python
from email.message import Message
from itertools import count
from termcolor import colored


#LDS.py
#Lab Deployment System for VMware ESXi
#Joe Dillig - AxiomSecurityLabs 10/26/17

Version='0.2.1'


#Change Log
# First Working Demo 10/26/17
# Integrated vmware RPC injection 11/3/17 (ver 0.1.1)
# Integrated VNC Configurations 4/10/18 (ver 0.2.1)

#Debug Function
def Debug(Message,Flag):
	file = open('Debug.txt', "a")
	file.write('['+Flag+'] '+Message+'\n')
	file.close()


#Imports
import sys
import argparse
import os.path
import subprocess
import ConfigParser


#Dependencies Check
#VMwareCMD (vSphere vCli)
ovftool_check = subprocess.check_output("which esxcli", shell=True)
Debug("Dependancy Check - esxcli","+")
if ovftool_check:
	#Debug log for the path of ovftool
	Debug("esxcli found in path","-")
	pass
else:
	Debug("oesxcli not found in path!","!")
	print("Unable to locate esxcli in path. Please install VMware vCLI on this machine")
	exit()

#VMware OVF Tool
ovftool_check = subprocess.check_output("which ovftool", shell=True)
Debug("Dependancy Check - ovftool","+")
if ovftool_check:
	#Debug log for the path of ovftool
	Debug("ovftool found in path","-")
	pass
else:
	Debug("ovftool not found in path!","!")
	print("Unable to locate ovftool in path. Please install VMware ovftool on this machine")
	exit()

#Process Arguments
#lds.py -s <ESXIP> -d <ESXDATASTORE> [-r <RESOURCE_POOL>] [-e <ENVIRONMENT>, -vm <ENVIRONMENT/INDIVIDUAL_VM>] -c <ENVIRONMENT_CONFIG_FILE> -p <Prefix>
parser = argparse.ArgumentParser(prog='LDS.py - Lab Deployment System Version '+Version, usage='./LDS.py -s <ESXIP> -d <ESXDATASTORE> -r <RESOURCE_POOL> -e <ENVIRONMENT> -c <ENVIRONMENT_CONFIG_FILE> -p <Prefix>  [-vnc]')

parser.add_argument('-s', '--server', help='ESX Server Ip', required=True)
parser.add_argument('-d', '--datastore', help='ESX Datastore Name', required=True)
parser.add_argument('-r', '--resourcepool', help='ESX Resource Pool', required=False)
parser.add_argument('-e', '--environment', help='VM Environment', required=True)
parser.add_argument('-vm', '--virtualmachine', help='VM Environment Individual VM', required=False)
parser.add_argument('-c', '--configfile', help='Environment Config File', required=True)
parser.add_argument('-p', '--prefix', help='Environment Prefix Name', required=True)
#parser.add_argument('-vnc', '--makevnc', help='Create .VNC Files', required=False, action=store_true, dest='boolean_switch')
makevnc = True
#parser.add_argument('-debug', '--debug', help='Enable Debugging', required=False, action=store_true, dest='boolean_switch')

#Parse and Store Args
args = parser.parse_args()

ESX_Server = args.server
ESX_Datastore = args.datastore
VM_Environment = args.environment
VM_Environment_ConfigFile = args.configfile
VM_Environment_Prefix = args.prefix

#Optional Parameters -> Check if empty
if args.resourcepool != None:
	ESX_ResourcePool = args.resourcepool
else:
	ESX_ResourcePool = ""

if args.virtualmachine != None:
	VM_VirtualMachine = args.virtualmachine






#ReadConfig Function - Reads Environment .ini file
def ReadConfig(configfile):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile) #Read the Enviroments Config .ini File
	#Debug("+","Function Called ReadConfig("configfile")")

def GetVMDeploymentMethod(configfile,VM):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(VM,"provision"))

def GetVMFile(configfile,VM):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(VM,"image"))

#Returns fingerprint of the ESX server from the ini file for esxcli commands
def GetESXFingerprint(ESX_Server):
	ESXConfig = ConfigParser.ConfigParser()
	ESXConfig.read("bin/ESXServers.ini") #Read the ESXServers Config .ini File
	return(ESXConfig.get(ESX_Server,"fingerprint"))

def GetESXVersion(ESX_Server):
	ESXConfig = ConfigParser.ConfigParser()
	ESXConfig.read("bin/ESXServers.ini") #Read the ESXServers Config .ini File
	return(ESXConfig.get(ESX_Server,"version"))

def GetESXDatastores(ESX_Server,ESX_Datastore):
	ESXConfig = ConfigParser.ConfigParser()
	ESXConfig.read("bin/ESXServers.ini") #Read the ESXServers Config .ini File
	return(ESXConfig.get(ESX_Server,"not working"))

def GetESXUsername(ESX_Server):
	ESXConfig = ConfigParser.ConfigParser()
	ESXConfig.read("bin/ESXServers.ini") #Read the ESXServers Config .ini File
	return(ESXConfig.get(ESX_Server,"username"))

def GetESXPassword(ESX_Server):
	ESXConfig = ConfigParser.ConfigParser()
	ESXConfig.read("bin/ESXServers.ini") #Read the ESXServers Config .ini File
	return(ESXConfig.get(ESX_Server,"password"))

def MakeNetParams(configfile,vm):
	ESXConfig = ConfigParser.ConfigParser()
	ESXConfig.read("bin/ESXServers.ini") #Read the ESXServers Config .ini File
	return(ESXConfig.get(ESX_Server,"password"))

def VM_Environment_VM_Count(configfile):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get("Environment","vmcount"))

def VM_Environment_VM_Name(configfile,vm_number):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	countstr = 'vm'+ str(vm_number)
	return(Config.get("Environment",countstr))

def VM_Environment_VM_Interface_Count(configfile,vm_name):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(vm_name,'interfaces'))

def VM_Environment_VM_Interface_Name(configfile,vm_name,if_number):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(vm_name,'interface'+str(if_number)))

def Create_vSwitch_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment):
	CreateString='esxcli -s '+ESX_Server+' -u '+ESX_Username+' -p '+ESX_Password+' -d '+ESX_Fingerprint+' network vswitch standard add -v '+VM_Environment_Prefix+'_'+VM_Environment
	return CreateString

def Create_Portgroup_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment,vSwitch,PortGroup):
	PortGroupString='esxcli -s '+ESX_Server+' -u '+ESX_Username+' -p '+ESX_Password+' -d '+ESX_Fingerprint+' network vswitch standard portgroup add -p '+PortGroup+' -v '+VM_Environment_Prefix+'_'+VM_Environment
	return PortGroupString

def Delete_vSwitch_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment):
	DeleteString='esxcli -s '+ESX_Server+' -u '+ESX_Username+' -p '+ESX_Password+' -d '+ESX_Fingerprint+' network vswitch standard remove -v '+VM_Environment_Prefix+'_'+VM_Environment
	return DeleteString

def Delete_VM_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment):
	DeleteString='esxcli -s '+ESX_Server+' -u '+ESX_Username+' -p '+ESX_Password+' -d '+ESX_Fingerprint+' network vswitch standard remove -v '+VM_Environment_Prefix+'_'+VM_Environment
	return DeleteString

def Get_ESX_Datastore_Mount(ESX_Server,ESX_Datastore):
	Config = ConfigParser.ConfigParser()
	Config.read('bin/ESXServers.ini') #Read the ESXServers Config .ini File
	return(Config.get(ESX_Server,ESX_Datastore+'mount'))

def VM_VNCenabled(configfile,vm_name):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(vm_name,'vncenabled'))

def VM_VNCport(configfile,vm_name):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(vm_name,'vncport'))

def VM_VNCpass(configfile,vm_name):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(vm_name,'vncpassword'))

def VM_VNCip(configfile,vm_name):
	Config = ConfigParser.ConfigParser()
	Config.read(configfile)
	return(Config.get(vm_name,'vncip'))


def Create_VM_VNC_String(configfile,vm_name,VM_Environment_Prefix,VM_Environment,ESX_Server,ESX_Datastore,ESX_Username,ESX_Password,vncport,vncpassword):
	Debug("Create_VM_VNC_String()","+")
	#Config = ConfigParser.ConfigParser()
	#Config.read(configfile) #Read the Environment ConfigFile
	ds_mount = Get_ESX_Datastore_Mount(ESX_Server,ESX_Datastore)
	vncstring = 'vmware-cmd -H '+ESX_Server+' -U '+ESX_Username+' -P '+ESX_Password+' '+ds_mount+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'.vmx setguestinfo RemoteDisplay.vnc.enabled true'+'\n'#VNC Enable
	vncstring = vncstring+'vmware-cmd -H '+ESX_Server+' -U '+ESX_Username+' -P '+ESX_Password+' '+ds_mount+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'.vmx setguestinfo RemoteDisplay.vnc.port '+vncport+'\n'#VNC Port #
	vncstring = vncstring+'vmware-cmd -H '+ESX_Server+' -U '+ESX_Username+' -P '+ESX_Password+' '+ds_mount+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'.vmx setguestinfo RemoteDisplay.vnc.password '+vncpassword+'\n'#VNC Password
	return vncstring


def Create_VM_RPC_String(configfile,vm_name,VM_Environment_Prefix,VM_Environment,ESX_Server,ESX_Datastore,ESX_Username,ESX_Password):
	Debug("Create_VM_RPC_String("+configfile+","+vm_name+")","+")
	Config = ConfigParser.ConfigParser()
	Config.read(configfile) #Read the Environment ConfigFile
	rpcvar_count = Config.get(vm_name,'rpcvars') #Count the number of RPCVARS from config file
	ds_mount = Get_ESX_Datastore_Mount(ESX_Server,ESX_Datastore) #Get DS UUID/Mount Point for RPC Injection
	rpcstring=""

	if rpcvar_count != "0":
		count=1
		Debug(str(rpcvar_count)+" rpcvar(s) found in vm config","-")
		rpcstring = 'vmware-cmd -H '+ESX_Server+' -U '+ESX_Username+' -P '+ESX_Password+' '+ds_mount+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'.vmx setguestinfo guestinfo.rpcvars '+str(rpcvar_count)+'\n'#Number of rpcvars
		while count <= int(rpcvar_count):
			rpcvarstring = Config.get(vm_name,'rpcvar'+str(count))
			Debug("rpcvar"+str(count)+": "+rpcvarstring,"-")
			rpcstring = rpcstring+'vmware-cmd -H '+ESX_Server+' -U '+ESX_Username+' -P '+ESX_Password+' '+ds_mount+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'.vmx setguestinfo guestinfo.rpcvar.'+str(count)+' "'+rpcvarstring+'"\n'
			count=count+1
		return rpcstring
	else:
		Debug("0 rpcvars found in vm config -> Returning 0 rpcvar string","-")
		rpcstring = 'vmware-cmd -H '+ESX_Server+' -U '+ESX_Username+' -P '+ESX_Password+' '+ds_mount+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'/'+VM_Environment_Prefix+'_'+VM_Environment+'_'+vm_name+'.vmx setguestinfo guestinfo.rpcvars 0\n'#No rpcvars -> Return RPC string stating 0 rpcvars
		return rpcstring






VMCount = VM_Environment_VM_Count(VM_Environment_ConfigFile)
ESX_Username = GetESXUsername(ESX_Server)
ESX_Password = GetESXPassword(ESX_Server)
ESX_Fingerprint = GetESXFingerprint(ESX_Server)

print colored('[+] Virtual Environment: '+VM_Environment, 'green')
print colored('[+] ESX Server: '+ESX_Server, 'green')
print colored('[+] Datastore: '+ESX_Datastore, 'green')
print colored('[+] VM Prefix: '+VM_Environment_Prefix, 'green')
print colored('[+] Resource Pool: '+ESX_ResourcePool, 'green')

count=1
while (count <= int(VMCount)):
	#print('[+] DEBUG: Count=',count,' VMCount=',VMCount)
	VM_Name = VM_Environment_VM_Name(VM_Environment_ConfigFile,count) #Get the name of the VM by using the VM number or count
	print colored(' [>] '+VM_Name, 'green')
	VM_Image_Path = 'environments/'+VM_Environment+'/'+VM_Name+'.ova'
	VM_DeploymentMethod = GetVMDeploymentMethod(VM_Environment_ConfigFile,VM_Name)
	OVF_Tool_Network_Params=''
	vSwitchString=''
	PortGroupString=''
	PortGroup=''

	#Create vSwitch String
	vSwitchString = Create_vSwitch_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment)

	#Create OVFTool network interface parameters
	if_number = VM_Environment_VM_Interface_Count(VM_Environment_ConfigFile,VM_Name)
	if_count=1

	while (if_count <= int(if_number)):
		if_name = VM_Environment_VM_Interface_Name(VM_Environment_ConfigFile,VM_Name,if_count)
		if (if_name == 'LabExternal'):
			OVF_Tool_Network_Params=OVF_Tool_Network_Params+'--net:'+if_name+'='+if_name+' '
		else:
			#Create PortGroup String
			PortGroup = Create_Portgroup_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment,VM_Environment_Prefix+'_'+VM_Environment,VM_Environment_Prefix+'_'+VM_Environment+'_'+if_name)
			PortGroupString=PortGroupString+PortGroup+'\n'
			OVF_Tool_Network_Params=OVF_Tool_Network_Params+'--net:'+if_name+'='+VM_Environment_Prefix+'_'+VM_Environment+'_'+if_name+' '

		#print('	[!] --net:'+if_name+'='+VM_Environment_Prefix+'_'+VM_Environment+'_'+if_name+' ')
		if_count=if_count+1

	#print('  [-] Network Parameters: '+OVF_Tool_Network_Params)
	if ESX_ResourcePool == "":
		#OVF_Tool_Deploy_String NO Resource Pool
		OVF_Tool_Deploy_String = ('ovftool -ds='+ESX_Datastore+' --name='+VM_Environment_Prefix+'_'+VM_Environment+'_'+VM_Name+' '+OVF_Tool_Network_Params+' --acceptAllEulas --disableVerification -dm='+VM_DeploymentMethod+' '+VM_Image_Path+' vi://'+ESX_Username+':'+ESX_Password+'@'+ESX_Server+'\n')
	else:
		#OVF_Tool_Deploy_String with Resource Pool
		OVF_Tool_Deploy_String = ('ovftool -ds='+ESX_Datastore+' --name='+VM_Environment_Prefix+'_'+VM_Environment+'_'+VM_Name+' '+OVF_Tool_Network_Params+' --acceptAllEulas --disableVerification -dm='+VM_DeploymentMethod+' '+VM_Image_Path+' vi://'+ESX_Username+':'+ESX_Password+'@'+ESX_Server+'/'+ESX_ResourcePool+'\n')

	#Create VNC Configuration per VM
	VM_vncenabled = VM_VNCenabled(VM_Environment_ConfigFile,VM_Name) #Get the boolean value of "vncenabled"
	if VM_vncenabled == "true":
		#if VNC is enabled, get port and password values
		Debug("VM_vncenabled=true","+")
		VM_vncip = VM_VNCip(VM_Environment_ConfigFile,VM_Name)
		VM_vncport = VM_VNCport(VM_Environment_ConfigFile,VM_Name)
		VM_vncpass = VM_VNCpass(VM_Environment_ConfigFile,VM_Name)
		print colored('  [>] VNC Port: '+VM_vncip+':'+VM_vncport, 'green') #Print VNC information during deployment
		#Create VNC Configuration Strings
		vncstring = Create_VM_VNC_String(VM_Environment_ConfigFile,VM_Name,VM_Environment_Prefix,VM_Environment,ESX_Server,ESX_Datastore,ESX_Username,ESX_Password,VM_vncport,VM_vncpass)

		#Create .vnc Connection Files
		if makevnc == True:
			file = open(VM_Environment_Prefix+'_'+VM_Environment+'_'+VM_Name+'.vnc', "a")
			file.write('[connection]'+'\n')
			file.write('host='+VM_vncip+'\n')
			file.write('port='+VM_vncport+'\n')
			file.close()
			print colored('  [>] VNC File: '+VM_Environment_Prefix+'_'+VM_Environment+'_'+VM_Name+'.vnc', 'green')

	else:
		VM_vncenabled == "false"
		Debug("VM_vncenabled=false","+")


	#Write the Deployment Script for the VM Environemnt
	DeployScriptFile = VM_Environment_Prefix+"_"+VM_Environment+"_DeployScript.sh"
	file = open(DeployScriptFile, "a")
	file.write('# '+VM_Environment_Prefix+' '+VM_Environment+' '+VM_Name+'\n') #Write VMname Comment into DeployScript
	file.write(vSwitchString+'\n') #Write vSwitch into Deploy Script
	file.write(PortGroupString) #Write Port Groups into Deploy Script
	file.write(OVF_Tool_Deploy_String) #Write OVFTOOL String into Deploy Script

	#Add rpcvars into DeployScript
	rpcvars = Create_VM_RPC_String(VM_Environment_ConfigFile,VM_Name,VM_Environment_Prefix,VM_Environment,ESX_Server,ESX_Datastore,ESX_Username,ESX_Password)



	#Write File
	file.write(rpcvars)
	if VM_vncenabled == "true":
		file.write(vncstring)
	file.close() #This close() is important
	Debug("Deploy Script Written: "+DeployScriptFile,"-")



	#Write the Clean-Up Script for the Environment
	#DeleteVMString = Delete_VM_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment)
	DeletevSwitchString = Delete_vSwitch_String(ESX_Server,ESX_Username,ESX_Password,ESX_Fingerprint,VM_Environment_Prefix,VM_Environment)

	CleanupScriptFile = VM_Environment_Prefix+"_"+VM_Environment+"_CleanupScript.sh"
	file = open(CleanupScriptFile, "a")
	file.write('# Cleanup Script for '+VM_Environment_Prefix+' '+VM_Environment+' '+VM_Name+'\n') #Write VMname Comment into Cleanup Script
	file.write(DeletevSwitchString+' > /dev/null\n')
	file.close()
	Debug("Cleanup Script Written: "+CleanupScriptFile,"-")

	count=count+1 #Increment

	Debug("Making DeployScript and CleanupScript Executable","-")
	subprocess.check_output("chmod +x "+DeployScriptFile, shell=True) #Make Deploy Script Executable
	subprocess.check_output("chmod +x "+CleanupScriptFile, shell=True) #Make Deploy Script Executable
	Debug("Complete","-")

print colored('[+] Complete','green')

