#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用脱壳器 v1.1 - 基于 unicorn 引擎模拟执行
原理：加载加壳二进制 → 模拟执行解压 stub → 检测 OEP → dump 内存
"""
import sys
import os
import struct
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE, UC_HOOK_INTR, UcError
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9


def analyze_elf(file_path):
    """分析 ELF 文件，提取关键信息"""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 检查 ELF 头
    if data[:4] != b'\x7fELF':
        print("[ERROR] 不是 ELF 文件")
        return None
    
    # 64 位 ELF
    is64 = data[4] == 2
    
    if not is64:
        print("[ERROR] 只支持 64 位 ELF")
        return None
    
    # 读取入口点
    e_entry = struct.unpack('<Q', data[24:32])[0]
    e_phoff = struct.unpack('<Q', data[32:40])[0]
    e_phentsize = struct.unpack('<H', data[54:56])[0]
    e_phnum = struct.unpack('<H', data[56:58])[0]
    
    print(f"入口点: 0x{e_entry:x}")
    print(f"程序头表偏移: 0x{e_phoff:x}")
    print(f"程序头数量: {e_phnum}")
    
    # 读取程序头
    segments = []
    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', data[ph_offset:ph_offset+4])[0]
        p_flags = struct.unpack('<I', data[ph_offset+4:ph_offset+8])[0]
        p_offset = struct.unpack('<Q', data[ph_offset+8:ph_offset+16])[0]
        p_vaddr = struct.unpack('<Q', data[ph_offset+16:ph_offset+24])[0]
        p_filesz = struct.unpack('<Q', data[ph_offset+32:ph_offset+40])[0]
        p_memsz = struct.unpack('<Q', data[ph_offset+40:ph_offset+48])[0]
        
        if p_type == 1:  # PT_LOAD
            segments.append({
                'vaddr': p_vaddr,
                'offset': p_offset,
                'filesz': p_filesz,
                'memsz': p_memsz,
                'flags': p_flags
            })
            print(f"  段 {i}: vaddr=0x{p_vaddr:x}, size=0x{p_memsz:x}, flags={p_flags}")
    
    return {
        'data': data,
        'entry': e_entry,
        'segments': segments
    }


def load_elf_into_emu(mu, file_path, base_addr=0):
    """加载 ELF 文件到 unicorn 模拟内存"""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    if data[:4] != b'\x7fELF':
        return None
    
    # 64 位
    if data[4] != 2:
        return None
    
    e_entry = struct.unpack('<Q', data[24:32])[0]
    e_phoff = struct.unpack('<Q', data[32:40])[0]
    e_phentsize = struct.unpack('<H', data[54:56])[0]
    e_phnum = struct.unpack('<H', data[56:58])[0]
    
    PAGE_SIZE = 0x1000
    
    loaded_segments = []
    
    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', data[ph_offset:ph_offset+4])[0]
        p_offset = struct.unpack('<Q', data[ph_offset+8:ph_offset+16])[0]
        p_vaddr = struct.unpack('<Q', data[ph_offset+16:ph_offset+24])[0]
        p_filesz = struct.unpack('<Q', data[ph_offset+32:ph_offset+40])[0]
        p_memsz = struct.unpack('<Q', data[ph_offset+40:ph_offset+48])[0]
        
        if p_type == 1:  # PT_LOAD
            addr = base_addr + p_vaddr
            aligned_addr = addr & ~(PAGE_SIZE - 1)
            aligned_size = ((addr - aligned_addr) + p_memsz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
            
            try:
                mu.mem_map(aligned_addr, aligned_size)
            except:
                pass  # 已经映射过了
            
            seg_data = data[p_offset:p_offset+p_filesz]
            mu.mem_write(addr, seg_data)
            loaded_segments.append((addr, p_memsz))
    
    return {
        'entry': base_addr + e_entry,
        'base': base_addr
    }


def generic_unpack(file_path, output_path=None):
    """通用脱壳：模拟执行到 OEP，dump 内存"""
    print(f"=== 通用脱壳器 v1.1 ===")
    print(f"目标: {file_path}")
    print()
    
    # 1. 分析主程序 ELF
    print("[1/5] 分析目标 ELF...")
    elf = analyze_elf(file_path)
    if not elf:
        return
    
    print()
    print("[2/5] 初始化 unicorn 引擎并加载共享库...")
    
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    PAGE_SIZE = 0x1000
    
    # 加载主程序
    for seg in elf['segments']:
        addr = seg['vaddr']
        size = seg['memsz']
        aligned_addr = addr & ~(PAGE_SIZE - 1)
        aligned_size = ((addr - aligned_addr) + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        
        print(f"  主程序段: 0x{aligned_addr:x} - 0x{aligned_addr+aligned_size:x}")
        try:
            mu.mem_map(aligned_addr, aligned_size)
        except:
            pass
        seg_data = elf['data'][seg['offset']:seg['offset']+seg['filesz']]
        mu.mem_write(addr, seg_data)
    
    # 加载 ld.so
    print()
    print("  加载动态链接器 ld.so...")
    ld_path = "/lib64/ld-linux-x86-64.so.2"
    ld_base = 0x10000000
    ld_info = load_elf_into_emu(mu, ld_path, ld_base)
    if ld_info:
        print(f"    ld.so 基址: 0x{ld_base:x}, 入口: 0x{ld_info['entry']:x}")
    
    # 加载 libc
    print("  加载 libc.so.6...")
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    libc_base = 0x20000000
    libc_info = load_elf_into_emu(mu, libc_path, libc_base)
    if libc_info:
        print(f"    libc 基址: 0x{libc_base:x}")
    
    # 栈
    STACK_ADDR = 0x7fff00000000
    STACK_SIZE = 1024 * 1024
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    rsp = STACK_ADDR + STACK_SIZE - 0x1000
    
    # 栈布局：argc -> argv[] -> NULL -> envp[] -> NULL -> auxv[] -> NULL
    # 我们从高地址往低地址写，最后调整 rsp
    
    # 先算一下需要多少空间
    # auxv: 7 项 (每项 16 字节) = 112 字节
    # envp: 1 个 NULL = 8 字节
    # argv: 1 个指针 + NULL = 16 字节
    # argc: 8 字节
    # arg0 字符串: 16 字节
    
    stack_bottom = STACK_ADDR + STACK_SIZE - 0x100
    
    # 写 arg0 字符串
    mu.mem_write(stack_bottom, b'/bin/ls\x00')
    arg0_addr = stack_bottom
    stack_bottom += 16
    
    # auxv（辅助向量）
    auxv = [
        (3, elf['segments'][0]['vaddr'] + 0x40),  # AT_PHDR（程序头表地址，近似值）
        (4, 56),       # AT_PHENT
        (5, 13),       # AT_PHNUM
        (6, 0x1000),   # AT_PAGESZ
        (7, ld_base),  # AT_BASE
        (9, elf['entry']),  # AT_ENTRY
        (0, 0),        # AT_NULL 结束
    ]
    
    for key, val in reversed(auxv):
        stack_bottom -= 16
        mu.mem_write(stack_bottom, struct.pack('<QQ', key, val))
    
    # envp 结束 NULL
    stack_bottom -= 8
    mu.mem_write(stack_bottom, struct.pack('<Q', 0))
    
    # argv: [arg0_ptr, NULL]
    stack_bottom -= 8
    mu.mem_write(stack_bottom, struct.pack('<Q', 0))  # argv[1] = NULL
    stack_bottom -= 8
    mu.mem_write(stack_bottom, struct.pack('<Q', arg0_addr))  # argv[0]
    
    # argc = 1
    stack_bottom -= 8
    mu.mem_write(stack_bottom, struct.pack('<Q', 1))
    
    mu.reg_write(UC_X86_REG_RSP, stack_bottom)
    print(f"  栈指针: 0x{stack_bottom:x}")
    
    # 2. 监控内存写入（检测解压过程）
    print()
    print("[2/4] 开始模拟执行，监控解压过程...")
    
    write_log = []
    
    def hook_mem_write(uc, access, address, size, value, user_data):
        write_log.append((address, size, value))
    
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    
    # 系统调用处理
    syscall_count = {'n': 0}
    
    def hook_syscall(uc, user_data):
        syscall_count['n'] += 1
        syscall_num = uc.reg_read(UC_X86_REG_RAX)
        
        # x86_64 Linux 系统调用约定
        # rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
        arg1 = uc.reg_read(UC_X86_REG_RDI)
        arg2 = uc.reg_read(UC_X86_REG_RSI)
        arg3 = uc.reg_read(UC_X86_REG_RDX)
        
        if syscall_count['n'] <= 10:
            print(f"  系统调用 #{syscall_count['n']}: {syscall_num} (args: {arg1}, {arg2}, {arg3})")
        
        # 处理常见系统调用
        if syscall_num == 60:  # exit_group
            print(f"  程序退出，code={arg1}")
            uc.emu_stop()
            return
        
        elif syscall_num == 1:  # write
            # fd=arg1, buf=arg2, count=arg3
            try:
                data = uc.mem_read(arg2, min(arg3, 100))
                text = bytes(data).decode('utf-8', errors='replace')
                if syscall_count['n'] <= 10:
                    print(f"    write: {text[:50]}")
            except:
                pass
            uc.reg_write(UC_X86_REG_RAX, arg3)  # 返回写入字节数
            return
        
        elif syscall_num == 9:  # mmap
            # 简化：返回一个固定的内存地址
            MMAP_BASE = 0x10000000
            mmap_size = (arg3 + 0xFFF) & ~0xFFF
            try:
                uc.mem_map(MMAP_BASE + syscall_count['n'] * 0x10000, mmap_size)
                uc.reg_write(UC_X86_REG_RAX, MMAP_BASE + syscall_count['n'] * 0x10000)
            except:
                uc.reg_write(UC_X86_REG_RAX, 0x10000000)
            return
        
        elif syscall_num == 0:  # read
            uc.reg_write(UC_X86_REG_RAX, 0)  # 返回 0（EOF）
            return
        
        elif syscall_num == 2:  # open
            uc.reg_write(UC_X86_REG_RAX, -2)  # ENOENT
            return
        
        elif syscall_num == 3:  # close
            uc.reg_write(UC_X86_REG_RAX, 0)
            return
        
        else:
            # 未知系统调用，返回 0
            uc.reg_write(UC_X86_REG_RAX, 0)
            return
    
    mu.hook_add(UC_HOOK_INTR, hook_syscall)
    
    # 3. 模拟执行
    print()
    print("[3/5] 模拟执行中...")
    
    # 从 ld.so 入口开始执行（动态链接器会负责加载和跳转到 main）
    entry = ld_info['entry'] if ld_info else elf['entry']
    print(f"  入口点: 0x{entry:x}")
    
    max_steps = 100000  # 最多执行 10 万条指令
    
    try:
        mu.emu_start(entry, 0, count=max_steps)
    except UcError as e:
        print(f"  执行停止: {e}")
    
    # 4. 收集结果
    print()
    print("[4/5] 分析执行结果...")
    
    print(f"  总内存写入次数: {len(write_log)}")
    
    # 统计写入的地址范围
    if write_log:
        min_addr = min(w[0] for w in write_log)
        max_addr = max(w[0] for w in write_log)
        print(f"  写入地址范围: 0x{min_addr:x} - 0x{max_addr:x}")
    
    # 当前 RIP
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"  当前 RIP: 0x{rip:x}")
    
    # 5. dump 内存
    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = base + "_unpacked.dump"
    
    print()
    print(f"正在 dump 内存到: {output_path}")
    
    # dump 整个地址空间
    dump_data = b''
    for seg in elf['segments']:
        addr = seg['vaddr']
        size = seg['memsz']
        try:
            data = mu.mem_read(addr, size)
            dump_data += data
        except:
            pass
    
    with open(output_path, 'wb') as f:
        f.write(dump_data)
    
    print(f"  dump 大小: {len(dump_data)} 字节")
    
    print()
    print("=" * 50)
    print("⚠️  注意：")
    print("  1. 这只是内存 dump，不是完整的可执行文件")
    print("  2. 需要手动修复 ELF 头和导入表（IAT）")
    print("  3. 可以用 IDA/Ghidra 加载 dump 文件分析")
    print("=" * 50)
    
    return output_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: generic_unpacker.py <加壳二进制> [输出路径]")
        sys.exit(1)
    
    target = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    
    generic_unpack(target, out)
