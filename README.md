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
