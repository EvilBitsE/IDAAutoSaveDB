


__VERSION__ = '1.1'
__AUTHOR__ = 'EvilBitsE'



import idaapi
import ida_kernwin
import ida_bytes
import idc
import ida_ida
import ida_idaapi
import ida_hexrays
import datetime
import time
import os



ASDBSaveTime = 0
ASDBCurrTime = 0
ASDBIsBigSize = True
def GetDBSize():
	global ASDBIsBigSize
	if(os.path.exists(idc.get_idb_path())):
		FileSize = os.path.getsize(idc.get_idb_path())
		if(FileSize < 0x40000000):#1G
			ASDBIsBigSize = False


def RunTimer():
	idaapi.msg('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n\n')
	global ASDBIsBigSize
	if ASDBIsBigSize:
		idaapi.msg('IDB is too big  or NOT Exists, AutoSaveDB  NOT Run')
	else:
		idaapi.msg('AutoSaveDB Run')
	idaapi.msg('\n\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')

def CheckAndSaveDB():
	global ASDBIsBigSize
	if ASDBIsBigSize:
		return
	global ASDBSaveTime
	global ASDBCurrTime
	oldTime = ASDBCurrTime
	ASDBCurrTime = time.time()
	if(ASDBCurrTime - oldTime > 1.5):
		if(ASDBCurrTime - ASDBSaveTime > 900.0):
			ASDBSaveTime = ASDBCurrTime
			idaapi.save_database(idc.get_idb_path(),0)


class AutoSaveDBHooks(idaapi.View_Hooks):
	def view_activated(self, view):
		if idaapi.get_widget_type(view) == idaapi.BWN_PSEUDOCODE:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(view) == idaapi.BWN_DISASM:
			CheckAndSaveDB()
		elif idaapi.get_widget_type(view) == idaapi.BWN_DUMP:
			CheckAndSaveDB()


class AutoSaveDB(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = "自动保存IDB"
	help = ""
	wanted_name = "AutoSaveDB"
	wanted_hotkey = ""

	def init(self):
		global hooks
		GetDBSize()
		RunTimer()
		now = time.time()
		global ASDBLastTime 
		ASDBLastTime = now
		hooks = AutoSaveDBHooks()
		re = hooks.hook()

		if idaapi.init_hexrays_plugin():
			addon = idaapi.addon_info_t()
			addon.id = "cn.hz.EvilBitsE"
			addon.name = "AutoSaveDB"
			addon.producer = "EvilBitsE"
			addon.url = "https://github.com/EvilBitsE/IDAAutoSaveDB"
			addon.version = "1.1.0.0"
			idaapi.register_addon(addon)
		return idaapi.PLUGIN_OK


	def run(self, arg):
		pass

	def term(self):
		pass


def PLUGIN_ENTRY():
	return AutoSaveDB()
