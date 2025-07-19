#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys

# MIPSレジスタ名と番号の対応
REGISTER_MAP = {
    '$zero': 0, '$0': 0,
    '$at': 1, '$1': 1,
    '$v0': 2, '$2': 2,
    '$v1': 3, '$3': 3,
    '$a0': 4, '$4': 4,
    '$a1': 5, '$5': 5,
    '$a2': 6, '$6': 6,
    '$a3': 7, '$7': 7,
    '$t0': 8, '$8': 8,
    '$t1': 9, '$9': 9,
    '$t2': 10, '$10': 10,
    '$t3': 11, '$11': 11,
    '$t4': 12, '$12': 12,
    '$t5': 13, '$13': 13,
    '$t6': 14, '$14': 14,
    '$t7': 15, '$15': 15,
    '$s0': 16, '$16': 16,
    '$s1': 17, '$17': 17,
    '$s2': 18, '$18': 18,
    '$s3': 19, '$19': 19,
    '$s4': 20, '$20': 20,
    '$s5': 21, '$21': 21,
    '$s6': 22, '$22': 22,
    '$s7': 23, '$23': 23,
    '$t8': 24, '$24': 24,
    '$t9': 25, '$25': 25,
    '$k0': 26, '$26': 26,
    '$k1': 27, '$27': 27,
    '$gp': 28, '$28': 28,
    '$sp': 29, '$29': 29,
    '$fp': 30, '$30': 30,
    '$ra': 31, '$31': 31,
}

# 命令の定義
INSTRUCTIONS = {
    # R-type
    'add': {'type': 'R', 'funct': 0x20},
    'sub': {'type': 'R', 'funct': 0x22},
    'and': {'type': 'R', 'funct': 0x24},
    'or':  {'type': 'R', 'funct': 0x25},
    'slt': {'type': 'R', 'funct': 0x2a},
    'sll': {'type': 'R', 'funct': 0x00},
    # I-type
    'addi': {'type': 'I', 'opcode': 0x08},
    'lw':   {'type': 'I', 'opcode': 0x23},
    'sw':   {'type': 'I', 'opcode': 0x2b},
    'beq':  {'type': 'I', 'opcode': 0x04},
    'bne':  {'type': 'I', 'opcode': 0x05},
    # J-type
    'j':    {'type': 'J', 'opcode': 0x02},
}

def to_binary(n, bits):
    """数値を指定されたビット数の2の補数表現のバイナリ文字列に変換する"""
    if n < 0:
        n = (1 << bits) + n
    return format(n, f'0{bits}b')

def parse_register(reg_str):
    """レジスタ文字列を数値に変換"""
    if reg_str not in REGISTER_MAP:
        raise ValueError(f"不明なレジスタです '{reg_str}'")
    return REGISTER_MAP[reg_str]

def assemble(line, symbol_table, current_address):
    """アセンブリコード1行を機械語に変換"""
    line = line.strip()
    line = line.replace(',', ' ').replace('(', ' ').replace(')', ' ')
    parts = line.split()

    if not parts:
        return ""

    mnemonic = parts[0].lower()
    if mnemonic not in INSTRUCTIONS:
        raise ValueError(f"サポートされていない命令です '{parts[0]}'")

    info = INSTRUCTIONS[mnemonic]
    op_type = info['type']
    operands = parts[1:]

    binary_code = ""

    if op_type == 'R':
        if len(operands) != 3:
            raise ValueError(f"'{mnemonic}' のオペランド数が正しくありません (3つ必要)")

        if mnemonic == 'sll':
            # sll $rd, $rt, shamt
            rd, rt = parse_register(operands[0]), parse_register(operands[1])
            try:
                shamt = int(operands[2])
                if not (0 <= shamt < 32):
                    raise ValueError(f"'{mnemonic}' のシフト量は0から31の間の整数である必要があります")
            except (ValueError, IndexError):
                raise ValueError(f"'{mnemonic}' のシフト量は数値である必要があります")
            rs = 0  # rs is not used in sll
            binary_code = f"000000{to_binary(rs, 5)}{to_binary(rt, 5)}{to_binary(rd, 5)}{to_binary(shamt, 5)}{to_binary(info['funct'], 6)}"
        else:
            # other R-type: op $rd, $rs, $rt
            rd, rs, rt = parse_register(operands[0]), parse_register(operands[1]), parse_register(operands[2])
            shamt = 0
            binary_code = f"000000{to_binary(rs, 5)}{to_binary(rt, 5)}{to_binary(rd, 5)}{to_binary(shamt, 5)}{to_binary(info['funct'], 6)}"

    elif op_type == 'I':
        opcode = to_binary(info['opcode'], 6)
        if mnemonic in ['lw', 'sw']:
            if len(operands) != 3:
                raise ValueError(f"'{mnemonic}' のオペランド形式が不正です (例: lw $t1, 0($t2))")
            rt, immediate_str, rs_str = operands[0], operands[1], operands[2]
            rt, rs = parse_register(rt), parse_register(rs_str)
            try:
                immediate = int(immediate_str)
            except ValueError:
                raise ValueError(f"'{mnemonic}' のオフセットは数値である必要があります")
            binary_code = f"{opcode}{to_binary(rs, 5)}{to_binary(rt, 5)}{to_binary(immediate, 16)}"
        
        elif mnemonic in ['beq', 'bne']:
            if len(operands) != 3:
                raise ValueError(f"'{mnemonic}' のオペランド数が正しくありません (3つ必要)")
            rs, rt = parse_register(operands[0]), parse_register(operands[1])
            label = operands[2]
            
            try:
                if label in symbol_table:
                    target_address = symbol_table[label]
                    offset = target_address - (current_address + 4)
                    immediate = offset >> 2
                else:
                    immediate = int(label)
            except ValueError:
                raise ValueError(f"'{mnemonic}' のラベルまたは即値が無効です: '{label}'")
            
            if not (-32768 <= immediate <= 32767):
                raise ValueError(f"'{mnemonic}' の分岐オフセットが16ビットの範囲外です: {immediate}")
            binary_code = f"{opcode}{to_binary(rs, 5)}{to_binary(rt, 5)}{to_binary(immediate, 16)}"

        else:  # addi
            if len(operands) != 3:
                raise ValueError(f"'{mnemonic}' のオペランド数が正しくありません (3つ必要)")
            rt, rs = parse_register(operands[0]), parse_register(operands[1])
            try:
                immediate = int(operands[2])
            except ValueError:
                raise ValueError(f"'{mnemonic}' の即値は数値である必要があります")
            binary_code = f"{opcode}{to_binary(rs, 5)}{to_binary(rt, 5)}{to_binary(immediate, 16)}"

    elif op_type == 'J':
        if len(operands) != 1:
            raise ValueError(f"'{mnemonic}' のオペランド数が正しくありません (1つ必要)")
        label = operands[0]
        try:
            if label in symbol_table:
                target_address = symbol_table[label]
            else:
                target_address = int(label)
        except ValueError:
            raise ValueError(f"'{mnemonic}' のラベルまたはアドレスが無効です: '{label}'")
        
        if target_address % 4 != 0:
            raise ValueError(f"ジャンプ先アドレス {target_address:#x} は4の倍数である必要があります")
        
        jump_target = target_address >> 2
        binary_code = f"{to_binary(info['opcode'], 6)}{to_binary(jump_target, 26)}"

    hex_code = format(int(binary_code, 2), '08x')
    return f"0x{hex_code[:4]}_{hex_code[4:]}"

def first_pass(lines):
    """1回目のパス: ラベルをシンボルテーブルに登録する"""
    symbol_table = {}
    address = 0  # 簡潔さのため、0番地から開始

    for line in lines:
        line = line.split('#')[0].strip()
        if not line:
            continue

        match = re.match(r'^\s*([a-zA-Z0-9_]+):\s*(.*)', line)
        if match:
            label, instruction_part = match.group(1), match.group(2).strip()
            if label in symbol_table:
                raise ValueError(f"ラベル '{label}' が重複して定義されています")
            symbol_table[label] = address
            if instruction_part:
                address += 4
        else:
            address += 4
    return symbol_table

def second_pass(lines, symbol_table):
    """2回目のパス: 各命令を機械語に変換する"""
    machine_codes = []
    address = 0

    for original_line in lines:
        line = original_line.split('#')[0].strip()
        if not line:
            continue

        instruction_part = line
        match = re.match(r'^\s*([a-zA-Z0-9_]+):\s*(.*)', line)
        if match:
            instruction_part = match.group(2).strip()

        if not instruction_part:
            machine_codes.append((original_line, None))
            continue

        try:
            code = assemble(instruction_part, symbol_table, address)
            machine_codes.append((original_line, code))
        except ValueError as e:
            raise ValueError(f"エラー (行: '{original_line.strip()}'): {e}")
        
        address += 4
    return machine_codes

def main():
    """複数行のアセンブリコードを受け取り、変換結果を表示する"""
    print("MIPS アセンブラ (複数行・ラベル対応)")
    print("アセンブリコードを入力してください。入力が終わったら Ctrl+D を押してください。")
    
    lines = sys.stdin.readlines()
    print("...入力受付完了。アセンブルを開始します...")

    try:
        symbol_table = first_pass(lines)
        machine_codes = second_pass(lines, symbol_table)

        print("\n--- 機械語出力 ---")
        for original_line, code in machine_codes:
            if code:
                print(f"{code}\t# {original_line.strip()}")

    except ValueError as e:
        print(e, file=sys.stderr)
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()
