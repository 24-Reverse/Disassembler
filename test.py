import disassembler


if __name__ == "__main__":
    disas = disassembler.Disassembler("bin/a.exe")
    disas.extract_bin_info()
    disas.show_info()
