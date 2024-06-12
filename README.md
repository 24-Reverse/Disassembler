# 反汇编器

## 简介

一个简单的反汇编器,支持:

1. 提取二进制文件基本信息
2. 以函数为单位进行反汇编
3. 提取函数列表, 第三方库列表, 函数调用图
4. 绘制控制流图

## 项目结构

```
DISASSEMBLER
│  disassembler.py          // 反汇编器类
│  README.md
│  test.py                  // 测试
│
├─bin                       // 存放二进制文件
│      a.exe                // PE 文件
│      a.out                // ELF 文件
│       
├─cfg                       // 存放 CFG 
│      a.cfg.png
│
└─source_code               // 存放源代码文件
        a.c
```

## 运行

通过提供命令行参数mode, 可以选择反汇编器使用线性模式(linear)还是递归模式(recursive), 打开终端, 键入: 

```
py -3 test.py --mode linear
# or
py -3 test.py --mode recursive
```