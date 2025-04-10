from binaryninja import BinaryView,MediumLevelILOperation
import keystone
from typing import List, Optional, Dict

def get_call(bv: BinaryView) -> List[Dict[str, any]]:
    """获取所有对 printf 的调用信息"""
    args_total = []
    printf_symbol = bv.get_symbol_by_raw_name("printf")  # 适用于未修饰的符号名
    if not printf_symbol:
        print("未找到 printf 符号")
        return args_total

    printf_addr = printf_symbol.address
    xrefs = bv.get_code_refs(printf_addr)  # 获取所有代码引用
    for xref in xrefs:
        calling_func = bv.get_functions_containing(xref.address)[0]
        mlil_instr = calling_func.get_low_level_il_at(xref.address).medium_level_il
        if mlil_instr.operation == MediumLevelILOperation.MLIL_CALL:
            args = mlil_instr.params
            print(f"找到调用参数: {args}")
            args_total.append({'address': xref.address, 'args': args})
    return args_total

def find_puts_addr(bv: BinaryView) -> Optional[int]:
    """查找 puts 函数地址"""
    for section_name, section in bv.sections.items():
        if section_name == ".plt.sec":
            start, end = section.start, section.end
            print(f"找到 .plt.sec 段: start={hex(start)}, end={hex(end)}")
            return find_functions_in_range(bv, start, end)
    print("未找到 .plt.sec 段")
    return None

def find_functions_in_range(bv: BinaryView, start: int, end: int) -> Optional[int]:
    """在指定范围内查找 puts 函数"""
    print(f"搜索范围: {hex(start)} - {hex(end)}")
    for func in bv.functions:
        if start <= func.start <= end and "puts" in func.name:
            print(f"找到函数: {func.name}, 地址: {hex(func.start)}")
            return func.start
    print("未找到 puts 函数")
    return None

def assemble_instruction(ks: keystone.Ks, asm: str, address: int) -> Optional[bytearray]:
    """汇编指令并返回编码"""
    try:
        encoding, _ = ks.asm(asm, address)
        return bytearray(encoding)
    except keystone.KsError as e:
        print(f"汇编失败: {e}")
        return None

def check_printf(bv: BinaryView) -> None:
    """检查并替换 printf 调用为 puts"""
    if str(bv.arch) != "x86_64":
        print("当前架构不支持，仅支持 x86_64 架构")
        return
    if bv.arch.address_size ==8:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    else :
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    call_info = get_call(bv)
    puts_addr = find_puts_addr(bv)
    if not puts_addr:
        print("未找到 puts 地址，无法继续")
        return
    print("开始替换 printf 调用为 puts")
    for call in call_info:
        args = call['args']
        address = call['address']
        if len(args) == 1 and args[0].operation == MediumLevelILOperation.MLIL_VAR:
            print(f"找到符合要求的 printf 调用: {hex(address)}")
            print(f"原始指令: {bv.get_disassembly(address)}")
            asm = f"call {hex(puts_addr)}"
            encoding = assemble_instruction(ks, asm, address)
            if encoding:
                bv.write(address, encoding)
                print(f"已将调用地址 {hex(address)} 的 printf 替换为 puts")
                print(f"替换后指令: {bv.get_disassembly(address)}")

                func = bv.get_functions_containing(address)[0]
                func.reanalyze()
                print(f"重新分析函数: {func.name}, 地址: {hex(func.start)}")
            else:
                print(f"替换失败: {hex(address)}")