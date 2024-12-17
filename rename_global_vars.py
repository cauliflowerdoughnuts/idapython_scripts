# Reference: https://research.openanalysis.net/spectreops/config/strings/cpp/2024/11/21/spectre-ops.html

import idaapi
import idc


# Decrypted strings were grabbed from x64dbg using: log {[esp+0x4]}:{s:[esp+0x4]}
strings = {
0x660D50:"76E894005c2DE86E40b032a0931D2ABC05C6eB36ACb1C18F5b640aD24Bbc9454",
0x660320:"OzYuOT02LjY1LDUw",
0x660334:"ZWN0bXtjYXJtZ2xjaXxjbWFya28sYW9t",
0x660358:"Y2xnbWRpbmFpaGRmZnpnZHJpYWssYW9t",
0x66037C:"1950BC4F01",
0x660388:"17B4C29833",
0x660394:"EEE592271B",
0x6603A0:"CullinetProgram",
0x6603B0:"680FDC",
0x6603B8:"ACDB39",
0x6603C0:"09-23",
0x6603C8:"rhnu.dll",
0x6603D4:"nyxhv",
0x6603DC:"B3C830CA-4433-CC3A-6737",
0x6603F4:"uhapy",
0x6603FC:"http://manjitaugustuswaters.com",
0x66041C:"jnml.php",
0x660428:"grfq.php",
0x660434:"tsml.zip",
0x660440:"tsml_nonir.zip",
0x660450:"wvxk.zip",
0x66045C:"wvxk_x64.zip",
0x66046C:"wsau.exe",
0x660478:"nico=",
0x660480:"&yfat=",
0x660488:"&zbce=",
0x660490:"&qiob=",
0x660498:"&jwrb=",
0x6604AC:"&nsmb=",
0x6604B4:"&inau=",
0x6604BC:"&wpof=",
0x6604C4:"&chja=",
0x6604CC:"&ehin=",
0x6604D4:"&vmzn=",
0x6604DC:"&ouej=",
0x6604E4:"&rzya=",
0x6604EC:"&cdyt=",
0x6604F4:"&rich=",
0x6604FC:"&clsx=",
0x660504:"&hwqy=",
0x66050C:"?selk=",
0x660514:"vdle",
0x660C08:"down/",
0x660C10:"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
0x660C40:"nircmdc.exe",
0x660C4C:"zip.exe",
0x660C54:"/c ping localhost -n 6 > nul &",
0x660C74:"/c ping localhost -n 10 > nul &",
0x660C94:"cout",
0x660C9C:"http://",
0x660CA4:"true",
0x660CAC:"false",
0x660CB4:"void",
0x660CBC:".asd",
0x660CCC:"[@]",
0x660CD8:"[|]",
0x660CDC:"[*]",
0x660CE0:".png",
0x660CE8:".exe",
0x660CF0:".lnk",
0x660CF8:".vbs",
0x660D00:".txt",
0x660D08:".7z",
0x660D0C:".bak",
0x660D14:" --headless=old --disable-gpu --remote-debugging-port=0 ",
0x6604A0:"MyTasks\\"
}


def set_hexrays_comment(address, text):
    
    # set comment in decompiled code
    try:
        cfunc = idaapi.decompile(address)
        tl = idaapi.treeloc_t()
        tl.ea = address
        tl.itp = idaapi.ITP_SEMI
        if cfunc is not None:
            cfunc.set_user_cmt(tl, text)
            cfunc.save_user_cmts() 
    except:
        print(f"Unable to comment pseudocode at {hex(address)}")


def set_comment(address, text):
    # Set in dissassembly
    idc.set_cmt(address, text,0)
    # Set in decompiled data
    set_hexrays_comment(address, text)


for addr, dec_str in strings.items():
    print(f'{hex(addr)}: {dec_str}')
    ida_name.set_name(addr, 'g_str_' + dec_str,  ida_name.SN_FORCE)
    set_comment(addr, dec_str)