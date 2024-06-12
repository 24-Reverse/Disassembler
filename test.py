# For using cmd args
import argparse
import disassembler

def args_init(**kwargs):
    '''
    添加和解析命令行参数
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        "-m",
        type = str,
        choices = ['linear', 'recursive'],
        default = 'recursive',
        help = "The disassemble mode, default by recursive"
    )
    # Add more cmd args below
    
    args = parser.parse_args()
    return args

def main(args):
    '''
    主函数, 创建反汇编器示例并进行反汇编
    '''
    bin_path = "bin/a"
    disasm= disassembler.Disassembler(bin_path)
    disasm.extract_func_table()
    disasm.extract_bin_info()
    
    #disasm.extract_call_graph()
    #disasm.draw_call_graph()  # 绘制函数调用图
    disasm.disassemble_section(args.mode)

if __name__ == "__main__":
    args = args_init()
    main(args)
    
