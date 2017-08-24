import logging

from PyQt5 import QtCore
from PyQt5 import QtWidgets

import idaapi
import idautils
import idc


__version__ = "1.0.0"


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# CONFIG
HIGHLIGHT_CALLS = True
HIGHLIGHT_PUSHES = True
HIGHLIGHT_ANTI_VM = True
HIGHLIGHT_ANTI_DEBUG = True
HIGHLIGHT_SUSPICIOUS_INSTRUCTIONS = True
# TODO ENABLE_COMMENTS option
# TODO REMOVE_COMMENTS option when clearing
# TODO KEEP_EXISTING_COLORS option


class Colors():
    """ Colors defined as standard 0xRRGGBB hexadecimal color value """
    CLEAR = 0xFFFFFF
    MINT = 0xAAFF77
    CORNFLOWER = 0x77AAFF
    FLAMINGO = 0xFC8EAC


def rgb_to_bgr_color(rgb_hex_color):
    """
    Return color in 0xBBGGRR format used by IDA from standard 0xRRGGBB hexadecimal color value.
    """
    r = rgb_hex_color & 0xFF0000
    g = rgb_hex_color & 0x00FF00
    b = rgb_hex_color & 0x0000FF
    return (b << 16) | g | (r >> 16)


def MySetColor(ea, rgb_color):
    """ Set RGB color of one instruction or data at ea. """
    # SetColor does not return success or failure
    idc.SetColor(ea, idc.CIC_ITEM, rgb_to_bgr_color(rgb_color))


def AppendComment(ea, s, repeatable=False):
    # see williutils and http://blogs.norman.com/2011/security-research/improving-ida-analysis-of-x64-exception-handling
    if repeatable:
        string = idc.RptCmt(ea)
    else:
        string = idc.Comment(ea)
    if not string:
        string = s  # no existing comment
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\n" + s
    if repeatable:
        idc.MakeRptCmt(ea, string)
    else:
        idc.MakeComm(ea, string)


class Highlighter(object):
    def __init__(self, color):
        self.color = color

    def highlight_instructions(self, ea, mnems):
        highlighted_eas = []
        for mnem in mnems:
            if self.highlight_instruction(ea, mnem):
                highlighted_eas.append(ea)
        return highlighted_eas

    def highlight_instruction(self, ea, mnem):
        """ Highlight instruction at ea if its mnemonic matches mnem. Return True if mnem matches. """
        if self.get_mnem(ea) == mnem:
            MySetColor(ea, self.color)
            return True
        return False

    def comment_eas(self, eas, text):
        for ea in eas:
            AppendComment(ea, text)
            logger.info("%s at 0x%x", text, ea)

    def get_mnem(self, ea):
        return idc.GetMnem(ea)

    def get_disasm(self, ea):
        return idc.GetDisasm(ea)


class ClearHighlighter(Highlighter):
    def __init__(self):
        self.color = Colors.CLEAR

    def highlight(self, ea):
        self.clear_color(ea)

    def clear_color(self, ea):
        """ Clear color highlight at ea. """
        MySetColor(ea, self.color)


class CallHighlighter(Highlighter):
    # TODO diff imported call vs. internal call
    mnems = ["call"]

    def highlight(self, ea):
        self.highlight_instructions(ea, self.mnems)


class PushHighlighter(Highlighter):
    # helps with highlighting x86 function call arguments
    # TODO highlighters helping with other calling conventions
    mnems = ["push"]

    def highlight(self, ea):
        self.highlight_instructions(ea, self.mnems)


class AntiVmHighlighter(Highlighter):
    mnems = [
        # from https://practicalmalwareanalysis.com/setcolorssiko-py/, also see Practical Malware Analysis, Chapter 17
        "sidt", "sgdt", "sldt", "smsw", "str", "in", "cpuid",
        "vpcext"
    ]

    def highlight(self, ea):
        highlighted_eas = self.highlight_instructions(ea, self.mnems)
        self.comment_eas(highlighted_eas, "Potential Anti-VM technique")


class AntiDebugHighlighter(Highlighter):
    # TODO SeDebugPrivilege
    mnems = ["rdtsc"]

    def highlight(self, ea):
        highlighted_eas = self.highlight_instructions(ea, self.mnems)
        self.comment_eas(highlighted_eas, "Potential Anti-Debug technique")

    @staticmethod
    def highlight_anti_debug_api_calls():
        anti_debug_apis = [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString",
        ]

        library_calls = {}  # api_name -> CodeRefsTo
        get_imports(library_calls)
        for api_name, codeRefsTo in library_calls.iteritems():
            if api_name in anti_debug_apis:
                logger.info("Potential Anti-Debug call %s imported", api_name)
                if codeRefsTo:
                    logger.info(" - %s called at %s", api_name, ", ".join(["0x%x" % x for x in codeRefsTo]))


def get_imports(library_calls):
    """ Populate dictionaries with import information. Return imported modules. """
    import_modules = []
    import_names_callback = make_import_names_callback(library_calls)
    for i in xrange(0, idaapi.get_import_module_qty()):
        import_modules.append(idaapi.get_import_module_name(i))
        idaapi.enum_import_names(i, import_names_callback)
    return import_modules


def make_import_names_callback(library_calls):
    """ Return a callback function used by idaapi.enum_import_names(). """
    def callback(ea, name, ordinal):
        """ Callback function to retrieve code references to library calls. """
        library_calls[name] = []
        for ref in idautils.CodeRefsTo(ea, 0):
            library_calls[name].append(ref)
        return True  # True -> Continue enumeration
    return callback


class SuspicousInstructionHighlighter(Highlighter):
    def highlight(self, ea):
        # TODO this is currently too noisy
        # eas_to_highlight = self.highlight_non_zero_xor(ea)
        # self.comment_eas(eas_to_highlight, "Suspicious XOR instruction")
        self.highlight_teb_access(ea)
        self.highlight_peb_access(ea)

    def highlight_non_zero_xor(self, ea):
        highlight_eas = []
        if self.get_mnem(ea) == "xor":
            if idc.GetOpnd(ea, 0) != idc.GetOpnd(ea, 1):
                ph = idc.PrevHead(ea)
                nh = idc.NextHead(ea)
                ip = idc.GetDisasm(ph)
                ia = idc.GetDisasm(nh)
                if ph or nh:
                    if not self.is_security_cookie(ea, ph, nh):
                        highlight_eas.append(ea)
                        MySetColor(ea, self.color)
        return highlight_eas

    def is_security_cookie(self, va, ph, nh):
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

    def highlight_teb_access(self, ea):
        if self.get_mnem(ea) in ["mov", "push"]:
            if "fs:[18h]" in self.get_disasm(ea) or "fs:18h" in self.get_disasm(ea):
                MySetColor(ea, self.color)
                self.comment_eas([ea], "Potential reading of TEB via fs:18h")

    def highlight_peb_access(self, ea):
        if self.get_mnem(ea) in ["mov", "push"]:
            if "fs:[30h]" in self.get_disasm(ea) or "fs:30h" in self.get_disasm(ea):
                MySetColor(ea, self.color)
                self.comment_eas([ea], "Potential reading of PEB via fs:30h")

    # Anti-Debug techniques using PEB
    #  BeingDebugged Flag
    """
    mov eax, dword ptr fs:[30h]
    mov ebx, byte ptr [eax+2]
    test ebx, ebx
    jz NoDebuggerDetected
    """
    #  ProcessHeap Flag push/pop
    """
    push dword ptr fs:[30h]
    pop edx
    cmp byte ptr [edx+2], 1
    jz DebuggerDetected
    """
    #  NtGlobalFlag
    """
    mov eax, large fs:30h
    cmp dword ptr ds:[eax+68h], 70h
    jz DebuggerDetected
    """


class HighlighterDialog(QtWidgets.QDialog):

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowCloseButtonHint)
        self.setWindowTitle("Highlighter v%s" % __version__)
        highlighter_layout = QtWidgets.QVBoxLayout()

        button_highlight = QtWidgets.QPushButton("&Highlight instructions")
        button_highlight.setDefault(True)
        button_highlight.clicked.connect(self.highlight)
        highlighter_layout.addWidget(button_highlight)

        button_clear = QtWidgets.QPushButton("&Clear all highlights")
        button_clear.clicked.connect(self.clear_colors)
        highlighter_layout.addWidget(button_clear)

        button_cancel = QtWidgets.QPushButton("&Close")
        button_cancel.clicked.connect(self.close)
        highlighter_layout.addWidget(button_cancel)

        self.setMinimumWidth(180)
        self.setLayout(highlighter_layout)

    def highlight(self):
        self.done(QtWidgets.QDialog.Accepted)
        highlighters = []
        if HIGHLIGHT_CALLS:
            highlighters.append(CallHighlighter(Colors.MINT))
        if HIGHLIGHT_PUSHES:
            highlighters.append(PushHighlighter(Colors.CORNFLOWER))
        if HIGHLIGHT_ANTI_VM:
            highlighters.append(AntiVmHighlighter(Colors.FLAMINGO))
        if HIGHLIGHT_ANTI_DEBUG:
            highlighters.append(AntiDebugHighlighter(Colors.FLAMINGO))
            # do this once per binary
            AntiDebugHighlighter.highlight_anti_debug_api_calls()
        if HIGHLIGHT_SUSPICIOUS_INSTRUCTIONS:
            highlighters.append(SuspicousInstructionHighlighter(Colors.FLAMINGO))
        highlight_instructions(highlighters)

    def clear_colors(self):
        self.done(QtWidgets.QDialog.Accepted)
        highlighters = []
        highlighters.append(ClearHighlighter())
        highlight_instructions(highlighters)


def highlight_instructions(highlighters):
    ea = idc.NextHead(0)
    while ea != idaapi.BADADDR:
        for h in highlighters:
            h.highlight(ea)
        ea = idc.NextHead(ea)


def main():
    dialog = HighlighterDialog()

    # Disable script timeout -> otherwise cancel script dialog pops up
    old_timeout = idaapi.set_script_timeout(0)
    dialog.exec_()
    # Restore the timeout
    idaapi.set_script_timeout(old_timeout)


if __name__ == "__main__":
    main()
