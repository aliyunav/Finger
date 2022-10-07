import idc
import idaapi
import idautils
import re


class FuncSigFeature:
    #using static class variable to avoid repeating loading.
    string_pool = idautils.Strings()
    def __init__(self):
        self.file_path = idc.get_input_file_path()

        self.code_list = ["",".text",".plt",".got","extern",".pdata",".bss"]

        self.control_ins_list = ["call","jc","jnc","jz","jnz","js","jns","jo","jno","jp",
                                "jpe","jnp","jpo","ja","jnbe","jae","jnb","jb","jnae","jbe",
                                "jna","je","jne","jg","jnle","jge","jnl","jl","jnge","jle","jng"]
       
        self.string_list = dict()
        for s in self.string_pool:
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


def get_func_feature(ea):
    content = dict()
    pfn = idaapi.get_func(ea)
    if pfn:
        func_addr = pfn.start_ea
        Func = FuncSigFeature()
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
