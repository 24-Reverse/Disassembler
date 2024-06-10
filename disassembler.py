'''
Disassembler
============

一个简单的反汇编器, 提供:
  1. 提取二进制文件基本信息
  2. 以函数为单位进行反汇编
  3. 提取函数列表, 第三方库列表, 函数调用图
  4.绘制控制流图
    
'''

import lief
from capstone import *
from os import *

class Disassembler:
    '''
    简单的反汇编器
    '''
    def __init__(self, binary_path:str, arch = CS_ARCH_X86, mode = CS_MODE_64):
        '''
        以给定的硬件架构初始化反汇编器
        
        # parameters
        binary_path: 二进制文件路径
        arch: 指令集,默认为x86
        mode: 寻址模式,默认64位
        '''
        # 反汇编时使用
        self.cs = Cs(arch, mode)
        self.binary = lief.parse(binary_path)
        
    def extract_bin_info(self):
        '''
        提取二进制文件的属性, 包括:
            - hash值
            - 头字段信息
            - section信息
            - 导入表
            - 导出表
            - got表
            - plt表
            - 字符串信息
            - 第三方库信息
        '''
        # TODO: 提取二进制文件属性
        # Just for example, feel free to modify
        self.hash = None
        self.header_info = None
        self.import_table = None
        self.export_table = None
        self.got = None
        self.plt = None
        self.str_info = None
        self.thrird_party_lib = None
        
    def disassemble_section(self, mode:str):
        '''
        对可执行程序代码段进行反汇编,以函数为单位给出反
        汇编指令序列
        
        # parameter
            mode: 反汇编模式
             - linear: 线性反汇编(默认)
             - recursive: 递归反汇编
        '''
        print("disassemble by", mode, "mode")
        if mode == "linear":
            self.__disassemble_linear()
        elif mode == "recursive":
            self.__disassemble_recursive()
        else:
            raise DisasModeError(
                "Invalid disassemble mode, please choose from linear\
                 and recursive"
            )
        
    def extract_func_table(self):
        '''
        提取函数表
        '''
        # TODO: 实现提取函数表
    
    def draw_control_flow_diagram(self, func):
        '''
        绘制指定函数的控制流图
        '''
        # TODO: 绘制指定函数的控制流图
        
    def write_to_xml(self):
        '''
        将分析的信息写入xml文件
        '''
        # TODO:写入xml文件
        
    def __disassemble_linear(self):
        '''
        私有方法,以线性模式进行反汇编
        '''
        # text_s
        
    def __disassemble_recursive(self):
        ''' 
        私有方法,以递归模式进行反汇编
        '''
        # TODO: 实现递归反汇编
        

class DisasModeError(Exception):
    '''
    反汇编模式异常
    只支持线性和递归两种
    '''
    def __init__(self, message):
        super().__init__(message)
        
# Add more exception classed below