


__VERSION__ = '1.0'
__AUTHOR__ = 'EvilBitsE'



import idaapi
import ida_kernwin
import ida_bytes
import idc
import ida_ida
import ida_idaapi
import pydemangler
import ida_hexrays
import datetime
import time
import os
import threading


ASDBmutex = threading.Lock()

ASDBLastTime = 0
ASDBFileSize = 0
'''1G'''
ADDBMAXSIZE = 0x40000000
def GetDBSize():
	global ASDBFileSize
	ASDBFileSize = os.path.getsize(idc.get_idb_path())


def CheckFileBigSize():
	global ASDBFileSize
	global ADDBMAXSIZE
	if(ASDBFileSize > ADDBMAXSIZE):
		return True
	return False
def RunTimer():
	idaapi.msg('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n\n')
	if CheckFileBigSize():
		idaapi.msg('DB is to big  AutoSaveDB  NOT Run')
	else:
		idaapi.msg('AutoSaveDB Run')
	idaapi.msg('\n\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')

def CheckAndSaveDB():
	if CheckFileBigSize():
		return
	global ASDBLastTime
	global ASDBmutex
	ASDBmutex.acquire()
	currentTime = datetime.datetime.now()
	#currentTime = now.strftime('%Y-%m-%d %H:%M:%S')
	if((currentTime - ASDBLastTime).seconds > 900):
		idaapi.save_database(idc.get_idb_path(),0)
		ASDBLastTime = currentTime
	ASDBmutex.release()
		
#https://hex-rays.com/products/ida/support/idapython_docs/ida_kernwin.html
#https://hex-rays.com/products/ida/support/idapython_docs/ida_kernwin.html#ida_kernwin.View_Hooks
'''
class AutoSaveDBHooks(idaapi.UI_Hooks):
	def populating_widget_popup(self, form, popup):
		if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(form) == idaapi.BWN_OUTPUT:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
			CheckAndSaveDB()
'''


class AutoSaveDBHooks(idaapi.View_Hooks):
	def view_activated(self, view):
		#idaapi.msg('view_activated')
		# view TWidget *
		#print(idaapi.get_widget_type(view))
		if idaapi.get_widget_type(view) == idaapi.BWN_PSEUDOCODE:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(view) == idaapi.BWN_DISASM:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(view) == idaapi.BWN_DUMP:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(view) == idaapi.BWN_STRUCTS:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(view) == idaapi.BWN_ENUMS:
			CheckAndSaveDB()



class AutoSaveDB(idaapi.plugin_t):
	'''idaapi.PLUGIN_HIDE  不在菜单显示'''
	flags = idaapi.PLUGIN_HIDE
	comment = "自动保存IDB"
	help = ""
	wanted_name = "AutoSaveDB"
	wanted_hotkey = ""

	def init(self):
		global hooks
		GetDBSize()
		RunTimer()
		now = datetime.datetime.now()
		global ASDBLastTime 
		ASDBLastTime = now
		#ASDBLastTime = now.strftime('%Y-%m-%d %H:%M:%S')
		hooks = AutoSaveDBHooks()
		re = hooks.hook()

		if idaapi.init_hexrays_plugin():
			addon = idaapi.addon_info_t()
			addon.id = "cn.hz.EvilBitsE"
			addon.name = "AutoSaveDB"
			addon.producer = "EvilBitsE"
			addon.url = "https://github.com/EvilBitsE/IDAAutoSaveDB"
			addon.version = "1.0.0.0"
			idaapi.register_addon(addon)
		return idaapi.PLUGIN_OK


	def run(self, arg):
		pass

	def term(self):
		pass


def PLUGIN_ENTRY():
	return AutoSaveDB()
