# 反汇编器

## 简介

一个简单的反汇编器,支持:

1. 提取二进制文件基本信息
2. 以函数为单位进行反汇编
3. 提取函数列表, 第三方库列表, 函数调用图
4. 绘制控制流图

## 项目结构

```
E:.
│  demo.py
│  disassembler.py      # 反汇编器类
│  README.md
│  test.py              # 主测试文件
│

├─assemble              # 存放反汇编结果
│      a.exe.txt
│      kernel.txt
│
├─bin                   # 存放二进制文件
│      a
│      a.exe
│      a.out
│      kernel
│
├─cfg                   # 存放控制流图
│      a.cfg.png
│
├─source_code           # 存放源代码
│      a.c
```

## 运行

查看帮助信息:(还在添加更多命令行参数)

```
Disassembler> python test.py --help                   
usage: test.py [-h] [--path PATH] [--mode {linear,recursive}] [--tofile {y,n}]

optional arguments:
  -h, --help            show this help message and exit
  --path PATH, -p PATH  The path of binary file
  --mode {linear,recursive}, -m {linear,recursive}
                        The disassemble mode, default by recursive
  --tofile {y,n}, -tf {y,n}
                        If y, then send the assemble to a file in dir assemble with same name as binary
```

以`递归模式(recursive)`反汇编bin/kernel文件, 输出到assemble/kernel.txt：

```
Disassembler> python test.py --path bin/kernel --mode recursive --tofile y
[Disassembler]: disassemble by recursive mode

Disassembler> cat assemble/kernel.txt
entry point: ffffff000000e030
function: ffffff000000e000, name: _ZN6kernel11kernel_main17h96af4d8e26f5a7d6E
function: ffffff000000e030, name: _start
function: ffffff000000e070, name: __rust_alloc_error_handler
......

entry_point::
0xffffff000000e030:	sub	rsp, 0x18
0xffffff000000e034:	mov	qword ptr [rsp], rdi
0xffffff000000e038:	mov	qword ptr [rsp + 8], rdi
0xffffff000000e03d:	lea	rax, [rip - 0x44]
0xffffff000000e044:	mov	qword ptr [rsp + 0x10], rax
0xffffff000000e049:	lea	rdi, [rip - 0xa1f]
0xffffff000000e050:	mov	esi, 0x7c
0xffffff000000e055:	call	0xffffff00000904e0
0xffffff000000e05a:	mov	rdi, qword ptr [rsp]
0xffffff000000e05e:	call	0xffffff000000e000
0xffffff000000e063:	int3	
0xffffff000000e064:	int3	
0xffffff000000e065:	int3	
0xffffff000000e066:	int3	
0xffffff000000e067:	int3	
0xffffff000000e068:	int3	
0xffffff000000e069:	int3	
0xffffff000000e06a:	int3	
0xffffff000000e06b:	int3	
0xffffff000000e06c:	int3	
0xffffff000000e06d:	int3	
0xffffff000000e06e:	int3	
0xffffff000000e06f:	int3	
0xffffff000000e070:	jmp	0xffffff000008f610
......
```