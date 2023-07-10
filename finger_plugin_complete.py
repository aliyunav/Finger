import idc
import idaapi
import idautils
import traceback
import threading
import queue 
import json
import base64
import hashlib
import platform
import requests

class Client(object):
    def __init__(self, url, headers, timeout):
        self.url = url
        self.headers = headers
        self.timeout = timeout


    def str2byte(self, l):
        for i in range(len(l)):
            l[i] = l[i].encode("utf-8")
        return l


    def byte2str(self, l):
        for i in range(len(l)):
            l[i] = l[i].decode("utf-8")
        return l


    def my_encode(self, msg_list):
        if "str" in str(type(msg_list[0])):
            msg_bytes_list = self.str2byte(msg_list)
        else:
            msg_bytes_list = msg_list
        msg_encode = list(map(base64.b64encode, msg_bytes_list))
        msg_str_list = self.byte2str(msg_encode)
        return msg_str_list


    def my_decode(self, msg):
        msg_bytes_list = self.str2byte(msg)
        msg_decode = list(map(base64.b64decode, msg_bytes_list))
        return msg_decode


    def gen_msg_py2(self, content):
        content_encode = dict()
        content_encode["extmsg"] = map(base64.b64encode, content["extmsg"])
        content_encode["ins_bytes"] = map(base64.b64encode, content["ins_bytes"])
        content_encode["ins_str"] = map(base64.b64encode, content["ins_str"])
        content_encode["func_name"] = content["func_name"]
        func_id = hashlib.md5(json.dumps(content_encode).encode("utf-8")).hexdigest()
        content_encode["md5"] = func_id
        msg = json.dumps(content_encode)
        return msg, func_id


    def gen_msg_py3(self, content):
        content_encode = dict()
        content_encode["extmsg"] = self.my_encode(content["extmsg"])
        content_encode["ins_bytes"] = self.my_encode(content["ins_bytes"])
        content_encode["ins_str"] = self.my_encode(content["ins_str"])
        content_encode["func_name"] = content["func_name"]
        func_id = hashlib.md5(json.dumps(content_encode).encode("utf-8")).hexdigest()
        content_encode["md5"] = func_id
        msg = json.dumps(content_encode)
        return msg, func_id


    def filter_func_symbol(self, func_symbol):
        if not func_symbol:
            return False
        filter_list = ["unknow", "nullsub"]
        for item in filter_list:
            if item in func_symbol:
                return False
        return True
  

    def recognize_function(self, content):
        version = platform.python_version()
        res = False
        func_id = ""
        symbol_dict = dict()
        
        if version.startswith('3'):
            msg, func_id = self.gen_msg_py3(content)
        else:
            msg, func_id = self.gen_msg_py2(content)
        try:
            self.session = requests.Session()
            res = self.session.post(self.url, data=msg, headers=self.headers, timeout=self.timeout)
            if res:
                symbol_dict[func_id] = self.get_func_symbol(res.text)
        except Exception as e:
            raise RuntimeError("upload function failed")
        return func_id, symbol_dict


    def get_func_symbol(self, res):
        func_symbol = ""
        if len(res) <= 4:
            return func_symbol
        try:
            msg_dict = json.loads(res)
            func_symbol = msg_dict["func_symbol"]
            if self.filter_func_symbol(func_symbol):
                return func_symbol
        except Exception as e:
            raise RuntimeError("get function symbol failed")
        return func_symbol

class FuncSigFeature:
    #using static class variable to avoid repeating loading.
    #this code may not secured under 7.7, removed
    #20230507
    #string_pool = idautils.Strings()
    def __init__(self,string_pool):
        self.file_path = idc.get_input_file_path()

        self.code_list = ["",".text",".plt",".got","extern",".pdata",".bss"]

        self.control_ins_list = ["call","jc","jnc","jz","jnz","js","jns","jo","jno","jp",
                                "jpe","jnp","jpo","ja","jnbe","jae","jnb","jb","jnae","jbe",
                                "jna","je","jne","jg","jnle","jge","jnl","jl","jnge","jle","jng"]
       #may not compatible for python 2
        self.string_list = dict()
        for s in string_pool:
            self.string_list[str(s)] = s.ea


    def get_file_structure(self):
        info = idaapi.get_inf_structure()
        arch = info.procName
        if info.is_be():
            endian = "MSB"
        else:
            endian = "LSB"
        return arch, endian
    

    def get_file_type(self):
        file_format = ""
        file_type = ""
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            file_format = "64"
        elif info.is_32bit():
            file_format = "32"
        if info.filetype == idaapi.f_PE:
            file_type = "PE"
        elif info.filetype == idaapi.f_ELF:
            file_type = "ELF"
        return file_format, file_type


    def get_module_info(self):
        module_info = ""
        if len(idc.ARGV) == 2:
            module_info = idc.ARGV[1]
        return module_info


    def byte2str(self, l):
        if "bytes" in str(type(l)):
            l = l.decode()
        return l


    def extract_const(self, ins_addr):
        const_str = ""
        op_str = idc.print_insn_mnem(ins_addr)
        if op_str not in self.control_ins_list:
            for i in range(2):
                operand_type = idc.get_operand_type(ins_addr, i)
                if operand_type == idc.o_mem:
                    const_addr = idc.get_operand_value(ins_addr, i)
                    if idc.get_segm_name(const_addr) not in self.code_list:
                        str_const = idc.get_strlit_contents(const_addr)
                        if str_const:
                            str_const = self.byte2str(str_const)
                            if (str_const in self.string_list) and (const_addr == self.string_list[str_const]):
                                const_str += str_const
                                break
        return const_str


    def get_ins_feature(self, start_ea):
        ins_str_list = list()
        ins_bytes_list = list()
        ins_list = list(idautils.FuncItems(start_ea))
        for ins_addr in ins_list:
            ins_bytes = idc.get_bytes(ins_addr, idc.get_item_size(ins_addr))
            ins_bytes_list.append(ins_bytes)
            ins_str = self.extract_const(ins_addr)
            ins_str_list.append(ins_str)
        return ins_bytes_list, ins_str_list

    
    def filter_segment(self, func_addr):
        ignore_list = ["extern",".plt",".got",".idata"]
        if idc.get_segm_name(func_addr) in ignore_list:
            return True
        else:
            return False


def get_func_feature(ea,string_pool):
    content = dict()
    pfn = idaapi.get_func(ea)
    if pfn:
        func_addr = pfn.start_ea
        Func = FuncSigFeature(string_pool)
        if Func.filter_segment(func_addr):
            return None
        arch, endian = Func.get_file_structure()
        file_format, file_type = Func.get_file_type()
        module_info = Func.get_module_info()
        ins_bytes_list, ins_str_list = Func.get_ins_feature(func_addr)
        content["extmsg"] = [arch, endian, file_format, file_type, module_info]
        content["ins_bytes"] = ins_bytes_list
        content["ins_str"] = ins_str_list
        content["func_name"] = idaapi.get_func_name(func_addr)
        return content
    else:
        return None

class FingerManager:
    def __init__(self):
        
        #idaapi.msg("[D]FingerManager:__init__\n")
        self.string_pool = ''
        #self.string_pool = idautils.Strings()
        
        self.url = "https://sec-lab.aliyun.com/finger/recognize/"
        self.headers = {'content-type': 'application/json'}
        self.timeout = 5
        self.client = None
        self.verify = False

    def recognize_function(self,func_feat):
        #idaapi.msg("[D]FingerManager:recognize_function\n")
        func_symbol = None
        try:
            self.client = Client(self.url, self.headers, self.timeout)
            #func_feat = ida_func.get_func_feature(start_ea)
            if func_feat:
                func_id, res = self.client.recognize_function(func_feat)
                if res and res[func_id]:
                    func_symbol = res[func_id]
        except Exception as e:
            idaapi.msg('[x] Exception occurred when recognize %s'%func_feat)
            idaapi.msg(traceback.format_exc())
        if func_symbol:
            func_symbol = str(func_symbol) 
        return func_symbol

    #def _internal_recognize_function(self, funcs, startpos,length, namelist,func_feat, queue):
    def _internal_recognize_function(self, funcs, startpos,length,func_feat, queue):
        #idaapi.msg("[D]FingerManager:_internal_recognize_function\n")
        #multi-threading version
        try:
            for ipfn in range(startpos,startpos+length,1):
                #func_name = namelist[ipfn]
                func_symbol = self.recognize_function(func_feat[ipfn])
                if(func_symbol):
                    queue.put([funcs[ipfn],func_symbol])
                else:
                    queue.put([funcs[ipfn],''])
            return
        except Exception as ea:
            idaapi.msg('[x] Exception occurred when recognize %s'%func_feat)
            idaapi.msg(traceback.format_exc())

    def recognize_selected_function(self, funcs):
        try:
            self.string_pool = idautils.Strings()

            #idaapi.msg("[D]FingerManager:recognize_selected_function\n")
            #modify this constant to allocate more threads.
            threads_count = 16
            if(len(funcs) < threads_count):
                threads_count = len(funcs)
            #start
            step = 1
            sum_step = 6
            idaapi.show_wait_box('HIDECANCEL\nFinger:Recognizing %d functions...\n[%d/%d] Getting function features' %(len(funcs),step,sum_step))
            #namelist = []
            func_feat = []
            for pfn in funcs:
                #namelist.append(idc.get_func_name(pfn.start_ea))
                func_feat.append( get_func_feature(pfn.start_ea,self.string_pool))
                #func_feat.append( ida_func.get_func_feature(pfn.start_ea))
            idaapi.msg(f"[N]Trying to recognize {len(funcs)} functions with {threads_count} threads")
            step = step + 1
            idaapi.replace_wait_box('HIDECANCEL\nFinger:Recognizing %d functions...\n[%d/%d] Setting up threads\nAllocating %d threads' %(len(funcs),step,sum_step,threads_count))
            thread_pool = []
            q = []
            results = [] 
            for i in range(threads_count):
                q.append(queue.Queue())
                #print("[T]Thread #%d gets %d to %d"%(i, i*len(funcs) /threads_count, i*len(funcs) /threads_count +len(funcs) /threads_count))
                #t = threading.Thread(target = self._internal_recognize_function, args = ( funcs, int(i*len(funcs) /threads_count) ,int(len(funcs) /threads_count ),namelist,func_feat,q[i]))
                t = threading.Thread(target = self._internal_recognize_function, args = ( funcs, int(i*len(funcs) /threads_count) ,int(len(funcs) /threads_count ),func_feat,q[i]))
                thread_pool.append(t)
                t.start()
            step = step + 1
            idaapi.replace_wait_box('HIDECANCEL\nFinger:Recognizing %d functions...\n[%d/%d] Waiting for threads to end' %(len(funcs),step,sum_step))
            for thread in thread_pool:
                thread.join()
            
            step = step + 1
            idaapi.replace_wait_box('HIDECANCEL\nFinger:Recognizing %d functions...\n[%d/%d] Getting thread results' %(len(funcs),step,sum_step))

            for i in range(threads_count):
                for j in range(q[i].qsize()):
                    results.append(q[i].get())
            print("[+]Successfully fetched %d func_symbol"%len(results))

            step = step + 1
            idaapi.replace_wait_box('HIDECANCEL\nFinger:Successfully fetched %d func_symbol\n[%d/%d] Setting up ida details' %(len(results),step,sum_step))
            failed_func_count = 0
            for r in results:
                if r[1] != '':
                    idc.set_color(r[0].start_ea, idc.CIC_FUNC, 0x98FF98)
                    idaapi.set_name(r[0].start_ea, r[1], idaapi.SN_FORCE)
                    idaapi.update_func(r[0])
                    #print("[+]Recognize %s: %s" %(r[0],r[1]))
                else:
                    failed_func_count = failed_func_count + 1
                    #print("[-]%s recognize failed" %(r[0]))
            
            step = step + 1
            idaapi.replace_wait_box('HIDECANCEL\nFinger:Done!\n[%d/%d] Done! ' %(step,sum_step))
            idaapi.hide_wait_box()
            print("[N]%d function(s) recognize failed" %(failed_func_count))
        except Exception as ea:
            idaapi.msg('[x] Exception occurred when recognize %s'%func_feat)
            idaapi.msg(traceback.format_exc())
    def recognize_function_callback(self,menupath):
        #idaapi.msg("[D]FingerManager:recognize_function_callback\n")
        ea = idaapi.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if pfn:
            func_name = idc.get_func_name(pfn.start_ea)
            func_symbol = self.recognize_function(pfn.start_ea)
            if func_symbol:
                idc.set_color(pfn.start_ea, idc.CIC_FUNC, 0x98FF98)
                idaapi.set_name(pfn.start_ea, func_symbol, idaapi.SN_FORCE)
                idaapi.update_func(pfn)
                #print("[+]Recognize %s: %s" %(func_name, func_symbol))
            #else:
            #    print("[-]%s recognize failed" %(func_name))
        else:
            print("[-]0x%x is not a function" %ea)


    def recognize_functions_callback(self,menupath):
        #idaapi.msg("[D]FingerManager:recognize_functions_callback\n")
        funcs = []
        for ea in idautils.Functions():
            funcs.append(idaapi.get_func(ea))
        self.recognize_selected_function(funcs)


class FingerUIManager:
    class UIHooks(idaapi.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            #idaapi.msg("[D]FingerUIManager:UIHooks:finish_populating_widget_popup\n")
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS: 
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeSelected", "Finger/")
            if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeFunction", "Finger/")


    class ActionHandler(idaapi.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            #idaapi.msg("[D]FingerUIManager:ActionHandler:__init__\n")
            idaapi.action_handler_t.__init__(self)
            self.name = name
            self.action_desc = idaapi.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback,  menupath=None):
            #idaapi.msg("[D]FingerUIManager:ActionHandler:register_action\n")
            self.callback = callback
            if not idaapi.register_action(self.action_desc):
                return False
            if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            #idaapi.msg("[D]FingerUIManager:ActionHandler:activate\n")
            self.callback(ctx)

        def update(self, ctx):
            #idaapi.msg("[D]FingerUIManager:ActionHandler:update\n")
            return idaapi.AST_ENABLE_ALWAYS


    def __init__(self, name):
        #idaapi.msg("[D]FingerUIManager:__init__\n")
        self.name = name
        self.mgr = FingerManager()
        self.hooks = FingerUIManager.UIHooks()

    def register_actions(self):
        
        #idaapi.msg("[D]FingerUIManager:register_actions\n")
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
        #idaapi.msg("[D]FingerUIManager:selected_function_callback\n")
        funcs = list(idaapi.getn_func, ctx.chooser_selection)
        if ctx.action == "Finger:RecognizeSelected":
            self.mgr.recognize_selected_function(funcs)


def check_ida_version():
    #idaapi.msg("[D]check_ida_version()\n")
    #idaapi.msg("[D]idaapi.IDA_SDK_VERSION =%d\n"%idaapi.IDA_SDK_VERSION)
    if idaapi.IDA_SDK_VERSION < 700:
        print("[-]Finger support 7.x IDA, please update your IDA version.")
        return False
    return True


class FingerPlugin(idaapi.plugin_t):
    wanted_name = "Finger"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        if check_ida_version():
            #idaapi.msg("[+]Finger plugin starts\n")
            manager = FingerUIManager(FingerPlugin.wanted_name)
            if manager.register_actions():
                #idaapi.msg("[D]idaapi.PLUGIN_OK\n")
                return idaapi.PLUGIN_OK
        
        #idaapi.msg("[D]idaapi.PLUGIN_SKIP\n")
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return FingerPlugin()
