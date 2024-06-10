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
        default = 'linear',
        help = "The disassemble mode, default by linear"
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
    disasm.extract_bin_info()
    disasm.disassemble_section(args.mode)

if __name__ == "__main__":
    args = args_init()
    main(args)
    