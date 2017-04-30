from __future__ import print_function

import enum
import logging
import operator

import idaapi
import idautils
import idc


g_logger = logging.getLogger(__name__)


class OP_TYPE(enum.Enum):
    REGISTER = 1
    MEM_REF = 2
    BASE_INDEX = 3
    BASE_INDEX_DISPLACEMENT = 4
    IMMEDIATE = 5
    IMMEDIATE_FAR = 6
    IMMEDIATE_NEAR = 7


def main():
    user_functions = get_user_functions()
    user_functions_xrefs = get_xrefs_to(user_functions)
    user_functions_xrefs_sorted = sorted(user_functions_xrefs.items(), key=operator.itemgetter(1), reverse=True)

    candidates_xor = find_unusual_xors(user_functions)
    candidates_shift = find_shifts(user_functions)
    candidates_mov = find_suspicous_movs(user_functions)

    weighted_functions = apply_weights(user_functions_xrefs_sorted, candidates_xor, candidates_shift, candidates_mov)
    print_top_functions(weighted_functions, 20)


def get_user_functions():
    user_functions = []
    for fva in idautils.Functions():
        f_attr = idc.GetFunctionAttr(fva, idc.FUNCATTR_FLAGS)
        if not f_attr & idc.FUNC_LIB and not f_attr & idc.FUNC_THUNK:
            user_functions.append(fva)
    return user_functions


def get_xrefs_to(functions):
    candidate_functions = {}
    for fva in functions:
        candidate_functions[fva] = len(list(idautils.XrefsTo(fva)))
    return candidate_functions


def find_unusual_xors(functions):
    candidate_functions = []
    for fva in functions:
        cva = fva
        while cva != idaapi.BADADDR and cva < idc.FindFuncEnd(fva):
            if idc.GetMnem(cva) == "xor":
                if idc.GetOpnd(cva, 0) != idc.GetOpnd(cva, 1):
                    g_logger.debug("suspicious XOR instruction at 0x%08X in function 0x%08X: %s", cva, fva,
                                   idc.GetDisasm(cva))
                    ph = idc.PrevHead(cva)
                    nh = idc.NextHead(cva)
                    ip = idc.GetDisasm(ph)
                    ia = idc.GetDisasm(nh)
                    if ip and ia:
                        g_logger.debug("Instructions: %s;  %s;  %s", ip, idc.GetDisasm(cva), ia)
                    if ph or nh:
                        if is_security_cookie(cva, ph, nh):
                            g_logger.debug("XOR related to security cookie: %s", idc.GetDisasm(cva))
                        else:
                            g_logger.debug("unusual XOR: %s", idc.GetDisasm(cva))
                            candidate_functions.append(fva)
                            break
            cva = idc.NextHead(cva)
    return candidate_functions


def is_security_cookie(va, ph, nh):
    # for security cookie check the xor should use ESP or EBP
    if idc.GetOpnd(va, 1) not in ["esp", "ebp", "rsp", "rbp"]:
        return False

    if "security" in idc.GetOpnd(ph, 1):
        return True
    elif "security" in idc.GetDisasm(nh):
        return True
    elif "security" in idc.GetDisasm(idc.NextHead(nh)):
        return True

    return False


def find_shifts(functions):
    candidate_functions = {}
    shift_mnems = set(["shl", "shr", "sar", "sal", "rol", "ror"])
    shift_mnems_len = len(shift_mnems)
    for fva in functions:
        shift_count = 0
        cva = fva
        while cva != idaapi.BADADDR and cva < idc.FindFuncEnd(fva):
            shift_count += 1
            if idc.GetMnem(cva) in shift_mnems:
                g_logger.debug("shift instruction: %s va: 0x%x function: 0x%x", idc.GetDisasm(cva), cva, fva)
            cva = idc.NextHead(cva)
        candidate_functions[fva] = 1 - ((shift_mnems_len - shift_count) / shift_mnems_len)
    return candidate_functions


def find_suspicous_movs(functions):
    candidate_functions = []
    for fva in functions:
        cva = fva
        while cva != idaapi.BADADDR and cva < idc.FindFuncEnd(fva):  # idc.GetFunctionAttr
            if idc.GetMnem(cva) == "mov":
                # identify register dereferenced writes to memory, e.g. mov [eax], cl
                if idc.GetOpType(cva, 0) == OP_TYPE.BASE_INDEX.value:
                    if idc.GetOpType(cva, 1) not in [OP_TYPE.IMMEDIATE.value, OP_TYPE.IMMEDIATE_FAR.value,
                                                     OP_TYPE.IMMEDIATE_NEAR.value]:
                        g_logger.debug("suspicious MOV instruction at 0x%08X in function 0x%08X: %s", cva, fva,
                                       idc.GetDisasm(cva))
                        candidate_functions.append(fva)
                        break
            cva = idc.NextHead(cva)
    return candidate_functions


def apply_weights(user_functions_sorted, candidates_xor, candidates_shift, candidates_mov):
    XOR_WEIGHT = 0.5
    SHIFT_WEIGHT = 0.5
    MOV_WEIGHT = 0.3
    XREF_WEIGHT = 0.2

    weighted_functions = {}
    max_xrefs = user_functions_sorted[0][1]
    for fva, xrefs in user_functions_sorted:
        weighted_functions[fva] = XREF_WEIGHT * (xrefs / max_xrefs)

    for fva in candidates_xor:
        weighted_functions[fva] += XOR_WEIGHT

    for fva, score in candidates_shift.iteritems():
        weighted_functions[fva] += SHIFT_WEIGHT * score

    for fva in candidates_mov:
        weighted_functions[fva] += MOV_WEIGHT

    return weighted_functions


def print_top_functions(weighted_functions, n):
    print("  n   Score     Function VA")
    for n, v in enumerate(sorted(weighted_functions.items(), key=operator.itemgetter(1), reverse=True)[:n], 1):
        fva, score = v
        print("%3d %10.05f  0x%08X " % (n, score, fva))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
