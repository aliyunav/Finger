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
