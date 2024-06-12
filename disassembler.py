'''
Disassembler
============

一个简单的反汇编器, 提供:
  1. 提取二进制文件基本信息
  2. 以函数为单位进行反汇编
  3. 提取函数列表, 第三方库列表, 函数调用图
  4.绘制控制流图
    
'''
import lief                         # For extract file info
import hashlib                      # For extract file info
import angr                         # For draw cfg
from capstone import *              # For disasm
from colorama import Fore, Style    # For colorful output
from colorama import init           # For colorful output
from collections import deque       # For recursive disasm
from capstone.x86_const import *    # For recursive disasm
from angrutils import *             # For draw cfg

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
        self.cs = Cs(arch, mode)
        # lief.ELF.Binary
        self.binary = lief.parse(binary_path)
        # 初始化颜色, 为了后面打印红色字符
        init()
        
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
        
    def disassemble_section(self, mode:str):
        '''
        对可执行程序.text节进行反汇编,以函数为单位给出反汇编指令序列
        
        # parameter
            mode: 反汇编模式
             - linear: 线性反汇编(默认)
             - recursive: 递归反汇编
        '''
        self.__print_red(f"[Disassembler]: disassemble by {mode} mode")
        if mode == "linear":
            self.__disassemble_linear()
        elif mode == "recursive":
            self.__disassemble_recursive()
        else:
            raise DisasmModeError(
                "Invalid disassemble mode, please choose from linear\
                 and recursive"
            )
        
    def extract_func_table(self):
        '''
        提取函数表
        '''
        # TODO: 实现提取函数表
    
    def draw_control_flow_diagram(self, func=None):
        '''
        绘制指定函数的控制流图
        '''
        # TODO: 绘制指定函数的控制流图
        if func is None:
            self.__draw_cfg()
        
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
        
    def __disassemble_linear(self):
        '''
        私有方法,以线性模式进行反汇编
        '''
        # 迭代寻找.text section
        text_section = None
        for section in self.sections:
            if section.name == '.text':
                text_section = section
        
        # 找不到.text section
        if text_section is None:
            raise TextSecError(
                "Missing text section"
            )
        
        # 获取.text节的虚拟地址和大小
        text_virtual_address = text_section.virtual_address
        text_size = text_section.size
        text_content = text_section.content
        
        # disasm
        # TODO: 添加函数名称
        self.insns = self.cs.disasm(
            text_content, text_virtual_address
        )
        for insn in self.insns:
            print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        
    def __disassemble_recursive(self):
        ''' 
        私有方法,以递归模式进行反汇编
        '''
        # 开启详细反汇编模式
        self.cs.detail = True
        
        # 迭代寻找.text section
        text_section = None
        for section in self.sections:
            if section.name == '.text':
                text_section = section
                
        # 找不到.text section
        if text_section is None:
            raise TextSecError(
                "Missing text section"
            )
        
        # 获取.text节的虚拟地址和大小
        text_virtual_address = text_section.virtual_address
        text_size = text_section.size
        text_content = text_section.content
            
        # 存放函数入口地址的队列
        q = deque()
        # 存放地址和是否已遍历的映射
        map = dict()
        # 二进制文件入口点地址
        entry_addr = self.binary.entrypoint
        q.append(entry_addr)
        self.__print_red(f"entry point: {entry_addr:016x}")
        
        # 将函数符号加入队列
        for func in self.binary.functions:
            q.append(func.address)
            self.__print_red(f"function: {func.address:016x}")
            
        # 递归反汇编
        while(len(q) != 0):
            addr = q.popleft()
            try:
                # 已经反汇编过, 跳过这个入口
                if map[addr] == True:
                    continue
            except:
                pass
            
            # 相对text节的偏移
            offset = addr - text_virtual_address
            valid_content = text_content[offset:]
            
            while(valid_content != ''):
                # 只解析一条指令
                # 虽然只有一条指令, 但返回的是一个迭代器
                insn_iter = self.cs.disasm(valid_content, text_virtual_address + offset, 1)
                
                # 从迭代器中取出单条指令
                try:
                    insn = next(insn_iter)
                except:
                    # print(valid_content)
                    break
                
                if insn.size == 0:
                    break
                
                # 标记这个入口点为已访问
                map[insn.address] = True
                # 打印指令
                print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
                # 更新指令解析位置
                valid_content = valid_content[insn.size:]
                # 更新偏移量
                offset += insn.size
                
                # 如果是控制流指令, 将其直接跳转入口加入队列中
                if self.__is_cflow_insn(insn):
                    target_addr = self.__get_ins_immediate_target(insn)
                    try:
                        visited = map[target_addr]
                    except:
                        # 没访问过, 则加入队列
                        if target_addr != 0:
                            q.append(target_addr)
                            self.__print_red(f"    --> new target: {target_addr:016x}")
                            
                    # 如果遇到无条件控制流指令或hlt指令, 则停止反汇编(跳转目标已经加入队列)
                    if self.__is_unconditional_cflow_insn(insn):
                        break
                    
                elif insn.id == X86_INS_HLT:
                    break
                    
            self.__print_red("--------------------------------------------")

    def __is_cflow_insn(self, insn: CsInsn):
        '''
        私有方法, 判断指令insn是否是控制流指令
        '''
        # 列表
        groups = insn.groups
        for group in groups:
            if self.__is_cflow_group(group):
                return True
            
    def __is_cflow_group(self, group:int):
        '''
        私有方法, 判断一个group是否属于控制流指令group
        '''
        return (group == CS_GRP_JUMP or group == CS_GRP_CALL\
            or group == CS_GRP_RET or  group == CS_GRP_IRET)
        
    def __get_ins_immediate_target(self, insn: CsInsn):
        '''
        私有函数, 获取指令的直接跳转地址
        只能获取直接跳转的地址, 若不是直接跳转则返回0
        '''
        operands = insn.operands
        for operand in operands:
            if operand.type == CS_OP_IMM:
                return operand.imm
            
        return 0
    
    def __is_unconditional_cflow_insn(self, insn: CsInsn):
        '''
        私有函数, 判断指令insn是否是无条件控制流指令
        '''
        id = insn.id
        if (id == X86_INS_JMP or
            id == X86_INS_LJMP or
            id == X86_INS_RET or
            id == X86_INS_RETF or
            id == X86_INS_RETFQ):
            return True
        
        return False
            
    def __print_red(self, text:str):
        '''
        私有方法, 辅助函数, 以红色打印字符串
        '''
        print(Fore.RED + text + Style.RESET_ALL)
    
    def __compute_hash(self, filepath: str):
        """
        私有方法，计算文件的哈希值
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
        '''
        私有方法，打印 ELF 文件属性
        '''
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
    
    def __draw_cfg(self):
        '''
        私有方法，生成控制流图
        '''
        file_path = self.bin_path
        p = angr.Project(file_path, auto_load_libs=False)

        # 使用快速生成方法生成 CFG
        cfg = p.analyses.CFGFast()

        # CFG 可视化
        file_name = file_path.split("/")[-1].split(".")[0]
        plot_cfg(cfg, "cfg/"+file_name+".cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  

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


class DisasmModeError(Exception):
    '''
    反汇编模式异常
    只支持线性和递归两种
    '''
    def __init__(self, message):
        super().__init__(message)

class TextSecError(Exception):
    '''
    .text section异常
    '''
    def __init__(self, message):
        super().__init__(message)

class FileTypeError(Exception):
    '''
    文件类型异常(当前只支持 PE/ELF 文件)
    '''
    def __init__(self):
        super().__init__(
            "Invalid file type, only PE/ELF file is supported currently"
        )

# Add more exception classed below
