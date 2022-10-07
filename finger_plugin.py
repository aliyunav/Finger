import idc
import idaapi
import idautils
import traceback
import threading
import queue 
from finger_sdk import client, ida_func


class FingerManager:
    def __init__(self):
        self.url = "https://sec-lab.aliyun.com/finger/recognize/"
        self.headers = {'content-type': 'application/json'}
        self.timeout = 5
        self.client = None
        self.verify = False

    def recognize_function(self,func_feat):
        func_symbol = None
        try:
            self.client = client.Client(self.url, self.headers, self.timeout)
            #func_feat = ida_func.get_func_feature(start_ea)
            if func_feat:
                func_id, res = self.client.recognize_function(func_feat)
                if res and res[func_id]:
                    func_symbol = res[func_id]
        except Exception as e:
            print('[x] Exception occured when recognize %s'%func_feat)
            print(traceback.format_exc())
        if func_symbol:
            func_symbol = str(func_symbol) 
        return func_symbol

    #def _internal_recognize_function(self, funcs, startpos,length, namelist,func_feat, queue):
    def _internal_recognize_function(self, funcs, startpos,length,func_feat, queue):
        #multi-threading version
        for ipfn in range(startpos,startpos+length,1):
            #func_name = namelist[ipfn]
            func_symbol = self.recognize_function(func_feat[ipfn])
            if(func_symbol):
                queue.put([funcs[ipfn],func_symbol])
            else:
                queue.put([funcs[ipfn],''])
        return

    def recognize_selected_function(self, funcs):
        namelist = []
        func_feat = []
        for pfn in funcs:
            #namelist.append(idc.get_func_name(pfn.start_ea))
            func_feat.append( ida_func.get_func_feature(pfn.start_ea))
        print("[N]Trying to recognize %d functions with 16 threads" %(len(funcs)))
        thread_pool = []
        q = []
        results = [] 
        for i in range(16):
            q.append(queue.Queue())
            print("[T]Thread #%d gets %d to %d"%(i, i*len(funcs) /16, i*len(funcs) /16 +len(funcs) /16))
            #t = threading.Thread(target = self._internal_recognize_function, args = ( funcs, int(i*len(funcs) /16) ,int(len(funcs) /16 ),namelist,func_feat,q[i]))
            t = threading.Thread(target = self._internal_recognize_function, args = ( funcs, int(i*len(funcs) /16) ,int(len(funcs) /16 ),func_feat,q[i]))
            thread_pool.append(t)
            t.start()
        
        for thread in thread_pool:
            thread.join()
        for i in range(16):
            for j in range(q[i].qsize()):
                results.append(q[i].get())
        print("[+]Successfully fetched %d func_symbol"%len(results))
        for r in results:
            if r[1] != '':
                idc.set_color(r[0].start_ea, idc.CIC_FUNC, 0x98FF98)
                idaapi.set_name(r[0].start_ea, r[1], idaapi.SN_FORCE)
                idaapi.update_func(r[0])
                print("[+]Recognize %s: %s" %(r[0],r[1]))
            else:
                print("[-]%s recognize failed" %(r[0]))

    def recognize_function_callback(self, menupath):
        ea = idaapi.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if pfn:
            func_name = idc.get_func_name(pfn.start_ea)
            func_symbol = self.recognize_function(pfn.start_ea)
            if func_symbol:
                idc.set_color(pfn.start_ea, idc.CIC_FUNC, 0x98FF98)
                idaapi.set_name(pfn.start_ea, func_symbol, idaapi.SN_FORCE)
                idaapi.update_func(pfn)
                print("[+]Recognize %s: %s" %(func_name, func_symbol))
            else:
                print("[-]%s recognize failed" %(func_name))
        else:
            print("[-]0x%x is not a function" %ea)


    def recognize_functions_callback(self, menupath):
        funcs = []
        for ea in idautils.Functions():
            funcs.append(idaapi.get_func(ea))
        self.recognize_selected_function(funcs)


class FingerUIManager:
    class UIHooks(idaapi.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeSelected", "Finger/")
            if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeFunction", "Finger/")


    class ActionHandler(idaapi.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            idaapi.action_handler_t.__init__(self)
            self.name = name
            self.action_desc = idaapi.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback,  menupath=None):
            self.callback = callback
            if not idaapi.register_action(self.action_desc):
                return False
            if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            self.callback(ctx)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    def __init__(self, name):
        self.name = name
        self.mgr = FingerManager()
        self.hooks = FingerUIManager.UIHooks()

    def register_actions(self):
        menupath = self.name
        idaapi.create_menu(menupath, self.name, "Help")

        action = FingerUIManager.ActionHandler("Finger:RecognizeFunctions", "Recognize all functions", "")
        action.register_action(self.mgr.recognize_functions_callback, menupath)
        action = FingerUIManager.ActionHandler("Finger:RecognizeFunction", "Recognize function", "")
        action.register_action(self.mgr.recognize_function_callback, menupath)
        recognize_action = FingerUIManager.ActionHandler("Finger:RecognizeSelected", "Recognize function")
        if recognize_action.register_action(self.selected_function_callback):
            self.hooks.hook()
            return True
        return False


    def selected_function_callback(self, ctx):
        funcs = map(idaapi.getn_func, ctx.chooser_selection)
        if ctx.action == "Finger:RecognizeSelected":
            self.mgr.recognize_selected_function(funcs)


def check_ida_version():
    if idaapi.IDA_SDK_VERSION < 700:
        print("[-]Finger support 7.x IDA, please update your IDA version.")
        return False
    return True


class FingerPlugin(idaapi.plugin_t):
    wanted_name = "Finger"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_MOD

    def init(self):
        if check_ida_version():
            idaapi.msg("[+]Finger plugin starts\n")
            manager = FingerUIManager(FingerPlugin.wanted_name)
            if manager.register_actions():
                return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return FingerPlugin()
