import angr
from angrutils import *

file_path = "bin/a.out"
p = angr.Project(file_path, auto_load_libs=False)

#使用快速生成方法生成CFG
cfg = p.analyses.CFGFast()

#使用完整生成方法生成CFG
#cfg1 = p.analyses.CFGEmulated()

#调用angr-utils库可视化
file_name = file_path.split("/")[-1].split(".")[0]
plot_cfg(cfg, "cfg/"+file_name+".cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  