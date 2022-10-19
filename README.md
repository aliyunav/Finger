# [20221019]IMPORTANT: FATAL EXCEPTION UNDER 7.7, REPAIRING.
-----
# Finger Multi-threading

An improved version of brilliant ida plugin finger, fixed 'always pop up' issue and implemented multi-threading to accelerate the recognition process.

**IMPORTANT: THIS IS PLUGIN IS STILL UNDER TEST AND HASNT PUBLISHED TO SITE YET!**

## Installation

* Download release version of source code.
* Replace the `finger_plugin.py` in `IDA_PATH/plugins`
* **Replace the `ida_func.py` in `%AppData%\Roaming\Python\Python38\site-packages\finger_sdk\client.py`** (differs from users)

Enjoy!

## Known issue

* After running the plugin, your IDA will stuck into no-response status, it takes time depends on your functions count. （UI Completed)

* Sometimes due to remote server SSL problem, you will receive exception:

  ```
  requests.exceptions.SSLError: HTTPSConnectionPool(host='sec-lab.aliyun.com', port=443): Max retries exceeded with url: /finger/recognize/ (Caused by SSLError(SSLEOFError(8, 'EOF occurred in violation of protocol (_ssl.c:1131)')))
  ```

  Most of time this is normal. If it in deed influenced your project , considering using original version.
* Python 3 supported, any issue of bug please propose.

* **`TypeError: object of type 'map' has no len()`** Solution manually modify `finger_plugin.py` at line 177:  
``` python
       # funcs = map(idaapi.getn_func, ctx.chooser_selection) # old
         funcs = list(idaapi.getn_func, ctx.chooser_selection)  # new
```  
![2022-10-07 22-19-17 00_00_10-00_01_10~1](https://user-images.githubusercontent.com/20926583/194583856-81b9a536-9918-4eec-bb44-ba6a308ec007.gif)









-----
# Finger
Finger, a tool for recognizing function symbol.

## Overview
Finger is a function symbol recognition engine for binary programs developed by Alibaba Cloud · Cloud Security Technology Lab, which aims to help security researchers identify unknown library functions in a given binary file.
Finger provides two ways to access core APIs of Finger function symbol recognition engine.

## Running environment
Now, Finger support python 2.7 and python 3, and requires IDA version >= 7.0.

## Finger python SDK
The python version must be the same as your IDAPython version.
~~~
pip install finger_sdk
~~~
After installing finger python SDK, you can check out the finger/exampls/recognize.py for more information.

## Finger IDA Plugin
Copy plugin/finger_plugin.py to your IDA_PATH/plugins path.
### upload function
The Finger IDA plugin supports single function, selected function, and all functions recognition. You can recognize function symbols in the menu bar, disassembly window, and function window.

Use Finger IDA plugin in the menu bar:
![1](images/1.png)

Use Finger IDA plugin in the disassembly window:
![2](images/2.png)

Use Finger IDA plugin in the function window:
![3](images/3.png)

### function symbol presentation
The successfully recognized function symbols will be highlighted in the disassembly window and function window.
![4](images/4.png)
