from binaryninja import *
from .patch_printf import check_printf

def printf2puts(bv:BinaryView):
    # 注册插件命令(
    check_printf(bv)

# 注册插件命令
PluginCommand.register("Printf to Puts", "Replace printf with puts", printf2puts)