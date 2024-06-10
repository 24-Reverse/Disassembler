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
import hashlib
from capstone import *

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
        self.bin_path = binary_path
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
            self.__extract_pe_info()
        elif isinstance(binary, lief.ELF.Binary):
            self.__extract_elf_info()
        else:
            raise FileTypeError()
        
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
            self.__show_pe_info()
        elif isinstance(binary, lief.ELF.Binary):
            self.__show_elf_info()
        else:
            pass
    
    def __compute_hash(self, filepath: str):
        """
        计算文件的哈希值
        """
        with open(filepath, 'rb') as infile:
            data = infile.read()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
        hash_info = {
            "md5": md5.digest(),
            "sha1": sha1.digest(),
            "sha256": sha256.digest()
        }
        return hash_info

    def __extract_pe_info(self):
        '''
        私有方法，提取 PE 文件属性
        '''
        binary = self.binary
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
    
    def __extract_elf_info(self):
        binary = self.binary

        # 计算文件的哈希值
        self.hash = self.__compute_hash(self.bin_path)

        # 头字段信息
        self.header_info = {
            "entrypoint": hex(binary.entrypoint),
            "arch": binary.header.machine_type,
            "abi": binary.header.identity_os_abi,
            "type": binary.header.file_type
        }

        # 节信息
        self.sectons = binary.sections

        # got 表
        self.got = binary.get_section(".got")

        # plt 表
        self.plt = binary.get_section(".plt")

        # 字符串信息
        self.str_info = binary.strings

        # 第三方库信息
        self.thrird_party_lib = binary.libraries

    def __show_pe_info(self):
        '''
        私有方法，打印 PE 文件属性
        '''
        # 哈希信息
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
            print(f"Virtual Address:    {hex(section.virtual_address)}")
            print(f"Size:               {section.size}")
            print(f"Entropy:            {section.entropy}\n")

        # 导入表
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
    
    def __show_elf_info(self):
        # 哈希信息
        hash_info = self.hash
        print("======================================================")
        print("Hash info")
        print("======================================================\n")
        print(f"md5:    {hash_info['md5']}")
        print(f"sha1:   {hash_info['sha1']}")
        print(f"sha256: {hash_info['sha256']}\n")

        # 文件头字段信息
        header_info = self.header_info
        print("======================================================")
        print("Header info")
        print("======================================================\n")
        print(f"Entry Point:    {header_info['entrypoint']}")
        print(f"Arch:           {header_info['arch']}")
        print(f"Abi:            {header_info['abi']}")
        print(f"Type:           {header_info['type']}\n")

        # 节信息
        print("======================================================")
        print("Sections")
        print("======================================================\n")
        for section in self.sectons:
            print(f"Section:            {section.name}")
            print(f"Virtual Address:    {hex(section.virtual_address)}")
            print(f"Size:               {section.size}")
            print(f"Offset:             {section.file_offset}\n")

        # got 表
        got_section = self.got
        if got_section:
            print("======================================================")
            print("GOT Table")
            print("======================================================\n")
            print(f"GOT: {got_section.content}\n")
            # for got_entry in got_section:
            #     print(f"0x{got_entry:02x}")

        # plt 表
        plt_section = self.plt
        if plt_section:
            print("======================================================")
            print("PLT Table")
            print("======================================================\n")
            print(f"PLT: {plt_section.content}\n")
            # for plt_entry in plt_section:
            #     print(f"0x{plt_entry:02x}")

        # 字符串信息
        str_info = self.str_info
        print("======================================================")
        print("String Table")
        print("======================================================\n")
        for string in str_info:
            print(string)
        print()

        # 第三库信息
        lib_info = self.thrird_party_lib
        print("======================================================")
        print("Libraries")
        print("======================================================\n")
        for lib in lib_info:
            print(lib)
        print()


class FileTypeError(Exception):
    '''
    文件类型异常(当前只支持 PE/ELF 文件)
    '''
    def __init__(self):
        super().__init__(
            "Invalid file type, only PE/ELF file is supported currently"
        )