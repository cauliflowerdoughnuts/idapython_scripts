# Reference: https://research.openanalysis.net/spectreops/config/strings/cpp/2024/11/21/spectre-ops.html

import idaapi
import idc


# Decrypted strings were grabbed from x64dbg using: log 0x{ecx}:{s:[esp+0x4]}
strings = {
0x660A7C:"76E894005c2DE86E40b032a0931D2ABC05C6eB36ACb1C18F5b640aD24Bbc9454",
0x7AF8B4:"OzYuOT02LjY1LDUw",
0x7AF8CC:"ZWN0bXtjYXJtZ2xjaXxjbWFya28sYW9t",
0x7AF8E4:"Y2xnbWRpbmFpaGRmZnpnZHJpYWssYW9t",
0x66098C:"1950BC4F01",
0x6606F8:"17B4C29833",
0x66080C:"EEE592271B",
0x660590:"CullinetProgram",
0x660B90:"680FDC",
0x660578:"ACDB39",
0x660A34:"09-23",
0x660860:"rhnu.dll",
0x660650:"nyxhv",
0x6605D8:"B3C830CA-4433-CC3A-6737",
0x6609A4:"uhapy",
0x6608F0:"http://manjitaugustuswaters.com",
0x660740:"jnml.php",
0x660638:"grfq.php",
0x660698:"tsml.zip",
0x660A4C:"tsml_nonir.zip",
0x660BF0:"wvxk.zip",
0x660B0C:"wvxk_x64.zip",
0x660B78:"wsau.exe",
0x6605C0:"nico=",
0x660B3C:"&yfat=",
0x660A04:"&zbce=",
0x660AAC:"&qiob=",
0x6608A8:"&jwrb=",
0x6607AC:"&nsmb=",
0x6606B0:"&inau=",
0x660608:"&wpof=",
0x66077C:"&chja=",
0x6609BC:"&ehin=",
0x6608C0:"&vmzn=",
0x6609EC:"&ouej=",
0x660944:"&rzya=",
0x660890:"&cdyt=",
0x66092C:"&rich=",
0x660794:"&clsx=",
0x660ADC:"&hwqy=",
0x6605A8:"?selk=",
0x660BD8:"vdle",
0x660BC0:"down/",
0x660560:"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
0x66083C:"nircmdc.exe",
0x660BA8:"zip.exe",
0x660680:"/c ping localhost -n 6 > nul &",
0x660974:"/c ping localhost -n 10 > nul &",
0x6605F0:"cout",
0x6607F4:"http://",
0x660AC4:"true",
0x660908:"false",
0x6609D4:"void",
0x660A94:".asd",
0x660620:"[@]",
0x6608D8:"[|]",
0x6607DC:"[*]",
0x660710:".png",
0x660668:".exe",
0x660B54:".lnk",
0x660764:".vbs",
0x660B24:".txt",
0x660728:".7z",
0x6606E0:".bak",
0x660A1C:" --headless=old --disable-gpu --remote-debugging-port=0 ",
0x6607C4:"MyTasks\\"
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