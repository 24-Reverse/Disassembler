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
    def __init__(self, binary_path, arch = CS_ARCH_X86, mode = CS_MODE_64):
        '''
        以给定的硬件架构初始化反汇编器
        
        # parameters
        binary_path: 二进制文件路径
        arch: 指令集,默认为x86
        mode: 寻址模式,默认64位
        '''
        self.hash = None
        self.header_info = None
        self.sectons = None
        self.import_table = None
        self.export_table = None
        self.got = None
        self.plt = None
        self.str_info = None
        self.thrird_party_lib = None

        # 反汇编时使用
        self.mode = Cs(arch, mode)
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
        binary = self.binary
        if isinstance(binary, lief.PE.Binary):
            # PE 文件
            # 获取文件的哈希值
            self.hash = {
                "md5": binary.authentihash_md5,
                "sha1": binary.authentihash_sha1,
                "sha256": binary.authentihash_sha256
            }

            # 头字段信息
            self.header_info = {
                "dos_header": binary.dos_header,            # DOS 头
                "file_header": binary.header,               # 文件头
                "optional_header": binary.optional_header   # 可选头
            }

            # 节信息
            self.sectons = binary.sections

            # 导入表
            if binary.has_imports:
                self.import_table = binary.imports

            # 导出表
            if binary.has_exports:
                self.export_table = binary.get_export()

            # 字符串信息
            # ！！！未测试！！！
            if binary.has_resources:
                manager = binary.resources_manager
                if manager.has_string_table:
                    self.str_info = manager.string_table
        
    def disassemble_section(self):
        '''
        对可执行程序代码段进行反汇编,以函数为单位给出反
        汇编指令序列
        '''
        # TODO: 实现以函数为单位的反汇编
        
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

    def show_info(self):
        '''
        打印二进制文件属性
        '''
        binary = self.binary
        if isinstance(binary, lief.PE.Binary):
            # 获取文件的哈希值
            hash_info = self.hash
            print("======================================================")
            print("Hash info")
            print("======================================================\n")
            print(f"md5:    {hash_info['md5']}")
            print(f"sha1:   {hash_info['sha1']}")
            print(f"sha256: {hash_info['sha256']}\n")

            # 文件头字段信息
            # DOS 头
            dos_header = self.header_info["dos_header"]
            print("======================================================")
            print("DOS Header")
            print("======================================================\n")
            print(dos_header)

            # 文件头
            file_header = self.header_info["file_header"]
            print("======================================================")
            print("File Header")
            print("======================================================\n")
            print(f"Machine:                    {file_header.machine}")
            print(f"Number of sections:         {file_header.numberof_sections}")
            print(f"Time Date Stamp:            {file_header.time_date_stamps}")
            print(f"Pointer to Symbol Table:    {file_header.pointerto_symbol_table}")
            print(f"Number of Symbols:          {file_header.numberof_symbols}\n")

            # 可选头
            optional_header = self.header_info["optional_header"]
            print("======================================================")
            print("Optional Header")
            print("======================================================\n")
            print(f"Magic:                      {optional_header.magic}")
            print(f"Size of Code:               {hex(optional_header.sizeof_code)}")
            print(f"Address of Entry Point:     {hex(optional_header.addressof_entrypoint)}")
            print(f"Base of Code:               {hex(optional_header.baseof_code)}")
            print(f"Base of Data:               {hex(optional_header.baseof_data)}")
            print(f"Image Base:                 {hex(optional_header.imagebase)}\n")

            # 节信息
            print("======================================================")
            print("Sections")
            print("======================================================\n")
            for section in self.sectons:
                print(f"Section:            {section.name}")
                print(f"Virtual Address:    {section.virtual_address}")
                print(f"Size:               {section.size}")
                print(f"Entropy:            {section.entropy}\n")

            # 导入
            has_imports = not (self.import_table is None)
            if has_imports:
                print("======================================================")
                print("Import Table")
                print("======================================================\n")
                for import_entry in self.import_table:
                    print(import_entry)

            # 导出表
            has_exports = not (self.export_table is None)
            if has_exports:
                print("======================================================")
                print("Export Table")
                print("======================================================\n")
                for export_entry in self.export_table:
                    print(export_entry)

            # 字符串信息
            has_str_info = not (self.str_info is None)
            if has_str_info:
                print("======================================================")
                print("String Table")
                print("======================================================\n")
                for string in self.str_info:
                    print(string)
