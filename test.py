# For using cmd args
import argparse
import disassembler

def args_init(**kwargs):
    '''
    添加和解析命令行参数
    '''
    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        "--path",
        "-p",
        type = str,
        default = "bin/kernel",
        help = "The path of binary file"
    )
    
    parser.add_argument(
        "--mode",
        "-m",
        type = str,
        choices = ['linear', 'recursive'],
        default = 'recursive',
        help = "The disassemble mode, default by recursive"
    )
    
    parser.add_argument(
        "--tofile",
        "-tf",
        type = str,
        choices = ['y', 'n'],
        default = 'n',
        help = "If y, then send the assemble to a file in dir assemble with same name as binary"
    )
    
    args = parser.parse_args()
    return args

def main(args):
    '''
    主函数, 创建反汇编器示例并进行反汇编
    '''
    disasm= disassembler.Disassembler(args)
    disasm.extract_bin_info()
    disasm.disassemble_section()
    disasm.extract_func_table()
    disasm.draw_call_graph()
    disasm.draw_control_flow_graph()

    
if __name__ == "__main__":
    args = args_init()
    main(args)
    
