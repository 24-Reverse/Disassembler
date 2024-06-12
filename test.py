import disassembler


if __name__ == "__main__":
    # disas = disassembler.Disassembler("bin/a.exe")
    disas = disassembler.Disassembler("bin/a.out")
    disas.extract_bin_info()
    disas.show_info()
    disas.draw_control_flow_diagram()