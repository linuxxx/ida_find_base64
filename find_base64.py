# -*- coding: utf-8 -*-
# IDA 7.x/9.x 兼容；
import re

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_ua

# 只在通过 encoder/decoder 任一门槛时输出
PRINT_ONLY_WHEN = "either"  # 可选: "encoder" / "decoder" / "either"

# ---- 编码器门槛 ----
ENCODER_MUST_ALL   = {"enc_step_3_4", "shift_2_4_6", "mask_0x3f"}
ENCODER_MUST_ANY   = {"div3_magic", "newline_76_crlf", "plus_0x80", "bitfield_aarch64", "halfword_utf16"}
ENCODER_MIN_RULES_HIT = 5     # 编码器总命中条数下限（只数ENC侧命中）
ENCODER_MIN_SCORE     = 8     # 编码器最小分

# ---- 解码器门槛 ----
DECODER_MUST_ALL   = {"shift_2_4_6", "mask_0x3f"}
DECODER_MUST_ANY   = {"whitespace", "group_3_4", "bitfield_aarch64"}
DECODER_MIN_RULES_HIT = 4     # 解码器总命中条数下限（只数DEC侧命中）
DECODER_MIN_SCORE     = 5     # 解码器最小分

# 可选：针对 .NET/IL2CPP 再加专属门槛（例如必须有 76 列换行+半字访问）
DOTNET_IL2CPP_STRICT = False
# 若启用，则编码器还需同时命中：
DOTNET_ENCODER_MUST_ALL = {"newline_76_crlf", "halfword_utf16"}

# ===================== 指令/工具 =====================
SHIFT_MNEMS = {
    "lsr", "lsl", "asr", "ror",       # AArch64/ARM
    "ubfx", "ubfiz", "bfi", "bfxil",
    "shr", "shl", "sar", "sal", "rol" # x86/x64 补充
}

def log(msg): print("[b64scan] " + msg)

def get_name_compat(ea):
    try:
        return ida_name.get_name(ea, ida_name.GN_VISIBLE)
    except TypeError:
        try:
            return ida_name.get_name(ea)
        except Exception:
            pass
    except Exception:
        pass
    try:
        return ida_funcs.get_func_name(ea)
    except Exception:
        return ""

def to_uint(val, bits=64):
    try:
        v = int(val)
    except Exception:
        return None
    if v < 0:
        v &= (1 << bits) - 1
    return v

def collect_func_features(func_ea):
    imms = set()
    mnems = []
    shifts = []
    has_ldrh = False
    has_strh = False

    for ea in idautils.FuncItems(func_ea):
        m = ida_ua.print_insn_mnem(ea).lower()
        mnems.append(m)
        if m == "ldrh": has_ldrh = True
        elif m == "strh": has_strh = True

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            continue

        for i in range(idaapi.UA_MAXOP if hasattr(idaapi, "UA_MAXOP") else 8):
            op = insn.ops[i]
            if op.type == ida_ua.o_void:
                break
            if op.type == ida_ua.o_imm:
                v = to_uint(op.value)
                if v is not None:
                    imms.add(v)
                    if m in SHIFT_MNEMS and v in (2, 4, 6):
                        shifts.append(v)
            elif op.type == ida_ua.o_displ:
                for cand in (getattr(op, "addr", None), getattr(op, "value", None)):
                    v = to_uint(cand)
                    if v is not None:
                        imms.add(v)

    return imms, mnems, shifts, has_ldrh, has_strh

# ===================== 规则判定 =====================
def rule_halfword_utf16(has_ldrh, has_strh):
    return has_ldrh or has_strh

def rule_shift_2_4_6(shifts): return len(set(shifts) & {2,4,6}) >= 2
def rule_bitfield_aarch64(mnems): s=set(mnems); return ("bfi" in s) or ("bfxil" in s)
def rule_plus_0x80(imms): return (128 in imms or 0x80 in imms)
def rule_newline_76_crlf(imms): return (76 in imms or 0x4C in imms) and (13 in imms or 0x0D in imms) and (10 in imms or 0x0A in imms)
def rule_div3_magic(imms): return (0x55555556 in imms) or (0xAAAAAAAB in imms)
def rule_enc_step_3_4(imms): return (3 in imms) and (4 in imms)
def rule_dec_whitespace(imms): return any(v in imms for v in (32,0x20,9,0x09,10,0x0A,13,0x0D))
def rule_dec_group_3_4(imms): return (3 in imms) and (4 in imms)
def rule_mask_0x3f_like(imms, utf16_half):
    return (0x3F in imms or 63 in imms) or (((0x7E in imms) or (126 in imms)) and utf16_half)

# ===================== 评分（与之前一致） =====================
def score_enc(imms, mnems, shifts, has_ldrh, has_strh):
    utf16 = rule_halfword_utf16(has_ldrh, has_strh)
    enc_score, hits = 0, []

    if rule_enc_step_3_4(imms):
        enc_score += 2; hits.append(("enc_step_3_4", "// - [ENC] 出现 +3/+4 步长（3→4 分组）"))
    if rule_mask_0x3f_like(imms, utf16):
        enc_score += 1; hits.append(("mask_0x3f", "// - [ENC] 存在 0x3F 掩码"))
    if rule_div3_magic(imms):
        enc_score += 2; hits.append(("div3_magic", "// - [ENC] 存在 /3 魔数 (0x55555556 或 0xAAAAAAAB)"))
    if rule_newline_76_crlf(imms):
        enc_score += 2; hits.append(("newline_76_crlf", "// - [ENC] 76 列换行 + CR/LF（.NET Convert 风格）"))
    if rule_plus_0x80(imms):
        enc_score += 1; hits.append(("plus_0x80", "// - [ENC] 出现 0x80 偏移（可能是 '=' 在表尾）"))
    if rule_shift_2_4_6(shifts):
        enc_score += 2; hits.append(("shift_2_4_6", "// - [ENC] 位移 2/4/6 组合（切分到 6bit）"))
    if rule_bitfield_aarch64(mnems):
        enc_score += 1; hits.append(("bitfield_aarch64", "// - [ENC] AArch64 位域合成 (BFI/BFXIL)"))
    if utf16:
        enc_score += 1; hits.append(("halfword_utf16", "// - [ENC] 半字访问 (UTF-16 字母表/输出)"))

    return enc_score, hits

def score_dec(imms, mnems, shifts, has_ldrh, has_strh):
    dec_score, hits = 0, []

    if rule_dec_whitespace(imms):
        dec_score += 1; hits.append(("whitespace", "// - [DEC] 处理空白字符"))
    if rule_dec_group_3_4(imms):
        dec_score += 1; hits.append(("group_3_4", "// - [DEC] 出现 3/4 组常数（解码配比）"))
    if rule_mask_0x3f_like(imms, rule_halfword_utf16(has_ldrh, has_strh)):
        dec_score += 1; hits.append(("mask_0x3f", "// - [DEC] 0x3F 掩码"))
    if rule_shift_2_4_6(shifts):
        dec_score += 2; hits.append(("shift_2_4_6", "// - [DEC] 位移 2/4/6 组合（4 sextets → 3 bytes）"))
    if rule_bitfield_aarch64(mnems):
        dec_score += 1; hits.append(("bitfield_aarch64", "// - [DEC] AArch64 位域合成 (BFI/BFXIL)"))

    return dec_score, hits

# ===================== 门槛判断（核心收敛逻辑） =====================
def _names(hits): return {k for (k, _) in hits}
def _reasons(hits): return [r for (_, r) in hits]

def pass_encoder_gate(enc_score, enc_hits):
    names = _names(enc_hits)
    # 必需 ALL
    if not ENCODER_MUST_ALL.issubset(names):
        return False
    # 必需 ANY（可选）
    if ENCODER_MUST_ANY and ENCODER_MUST_ANY.isdisjoint(names):
        return False
    # 数量&分数
    if len(enc_hits) < ENCODER_MIN_RULES_HIT:
        return False
    if enc_score < ENCODER_MIN_SCORE:
        return False
    # 可选的 .NET/IL2CPP 严格门槛
    if DOTNET_IL2CPP_STRICT and (not DOTNET_ENCODER_MUST_ALL.issubset(names)):
        return False
    return True

def pass_decoder_gate(dec_score, dec_hits):
    names = _names(dec_hits)
    if not DECODER_MUST_ALL.issubset(names):
        return False
    if DECODER_MUST_ANY and DECODER_MUST_ANY.isdisjoint(names):
        return False
    if len(dec_hits) < DECODER_MIN_RULES_HIT:
        return False
    if dec_score < DECODER_MIN_SCORE:
        return False
    return True


def annotate_func(func_ea, header, reasons):
    body = header + ("\n" + "\n".join(reasons) if reasons else "")
    try:
        ida_funcs.set_func_cmt(ida_funcs.get_func(func_ea), body, True)
    except Exception:
        pass

# ===================== 主流程 =====================
def scan_all():
    hits = []
    for f_ea in idautils.Functions():
        imms, mnems, shifts, has_ldrh, has_strh = collect_func_features(f_ea)

        enc_score, enc_hits = score_enc(imms, mnems, shifts, has_ldrh, has_strh)
        dec_score, dec_hits = score_dec(imms, mnems, shifts, has_ldrh, has_strh)

        encoder_ok = pass_encoder_gate(enc_score, enc_hits)
        decoder_ok = pass_decoder_gate(dec_score, dec_hits)

        # 按配置决定是否输出
        if PRINT_ONLY_WHEN == "encoder":
            if not encoder_ok: continue
            kind = "encoder"
        elif PRINT_ONLY_WHEN == "decoder":
            if not decoder_ok: continue
            kind = "decoder"
        else:  # "either"
            if not (encoder_ok or decoder_ok): continue
            if encoder_ok and (not decoder_ok):
                kind = "encoder"
            elif decoder_ok and (not encoder_ok):
                kind = "decoder"
            else:
                # 两者都通过，按分数高者；相等默认 encoder
                kind = "encoder" if enc_score >= dec_score else "decoder"

        # 生成注释（顺序固定、只打印命中的条目）
        enc_order = [
            "enc_step_3_4","mask_0x3f","div3_magic","newline_76_crlf",
            "plus_0x80","shift_2_4_6","bitfield_aarch64","halfword_utf16"
        ]
        dec_order = ["whitespace","group_3_4","mask_0x3f","shift_2_4_6","bitfield_aarch64"]

        enc_reason_map = dict(enc_hits)
        dec_reason_map = dict(dec_hits)
        reasons = []
        for k in enc_order:
            if k in enc_reason_map: reasons.append(enc_reason_map[k])
        for k in dec_order:
            if k in dec_reason_map: reasons.append(dec_reason_map[k])

        header = f"// Base64 {kind} candidate | enc={enc_score}, dec={dec_score}"
        annotate_func(f_ea, header, reasons)
        hits.append((f_ea, kind, enc_score, dec_score))

    hits.sort(key=lambda x: (x[1] == "encoder", x[2], x[3]), reverse=True)
    log("命中函数数量: %d" % len(hits))
    for ea, kind, es, ds in hits:
        nm = get_name_compat(ea) or "(no name)"
        log("0x%X  %-8s  enc=%-2d dec=%-2d  %s" % (ea, kind, es, ds, nm))

    ida_kernwin.info("Base64 规则扫描完成：命中 %d 个函数" % len(hits))

if __name__ == "__main__":
    scan_all()
