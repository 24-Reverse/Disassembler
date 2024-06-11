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
# For colorful output
from colorama import Fore, Style
from colorama import init
# For recursive disasm
from collections import deque
# For recursive disasm
from capstone.x86_const import *

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
        # Just for example, feel free to modify
        self.hash = None
        self.header_info = None
        
        # lief.ELF.section的迭代器
        self.sections = self.binary.sections
        
        self.import_table = None
        self.export_table = None
        self.got = None
        self.plt = None
        self.str_info = None
        self.thrird_party_lib = None
        
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

# Add more exception classed below