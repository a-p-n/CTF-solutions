from string import ascii_uppercase, digits
alphabet = ascii_uppercase + digits

known_plaintext_part = "lactf{"

intro = "On this Valentine's day, I wanted to show my love for professor Paul Eggert. This challenge is dedicated to him. Enjoy the challenge!"
ciphertext = '''Br olzy Jnyetbdrc'g xun, V avrkkr gb sssp km frja sbv kvflsffoi Jnuc Sathrg. Wkmk gytjzyakz mj jsqvcmtoh rc bkd. Canjc kns puadlctus!
L xyw fmoxztu va tai szt, dbiazb yiff mt Zzhbo 1178 gyfyjhuzw vhtkqfy sniu eih vbsel edih tpcvftz, xcie ysnecsmge hbucqtu qt wcorr crzhg-olhm srr gkh gdsjxqh gnxxl rtr guez jewr klkkgak dx uuka nnv hmvwbj gmv glz fvyh, jueg eww oq i wuqglh Z lrigjsss ynch xun esivmpwf: "oof hvrb frtbrq it Kcmlo?"
C ltzihfvxsq ghp abqs qrfzf glvx de HN bnty gocr gr:
Eiaj zek rvocf vnriiu ob Puiza. Xegjy webrvbvrj. Frat s vgxhidm kepldrv gbq phxgv.
Ehlb'w wuhu C ixyzchlr, ilc srez foq e wxzb sdz nrbrb. Eej W und siieesx nd pvvgb zvr pooi. B fox wc nrax v pedgei aex phvqe. Hqdru pc tvvtrv, C zyoxvxsq ghq wyvbg yzgmex KEKN=/ife/lgcyr/qg/ejl:$TNXC, eej hurn mlp qowtswvqn:
wrm ~cuamyh/umlofikjayrvplzcwm.gdg | pzwj
ropgf{qvjal_dfuxaxzbk_gbq_jeci_hdt_nr_hdr_eexij}
Yiqqeefl, cywfylnt zlrv finqvyq sqii sm oncw.
Apxcf ipv yah v lrrt ubujs, rnsm kbb jvrvpce anaazio eo ecvn bq abv TA wh bos aiahovr qojp.
L vhclachyyc mirj hueoaoc xfs uhhjim ove, gybwwc vmdslbc qbai xyk fvthk uasnslf rngr pc dsez, rvcpo vrjcse fhqed afsh K ycnv Zkxkfg fcjeys Q-g Vushrro Ayu Wf Phxeetnr Wjf Gkl Uelusl Slm xr fwm rncwti hfhkk lcamhi. D ary wa gozig wfcwe. Humqiiobt, V lzsdcr xrkj ng xci wxcag ow nue tzufvrbrp, efh ntrqbrh vw Vmuret elyajm nwilrh cmj nsnq uftgr wh opaorh jrku ar. "V wbpw akttp ybx," oy vvfcyl. P kpw dfidrw or qb wlac sbq ibygh ftzl jazkc eq vy mjzqjrvj vvf seegb [PCUHDCYEXI FL HUR IENRRESN].
V eorowiv jihk as fivx, aaacvns ofip gyxvpnp prcaqxl slubkbhv' ecwxw vru ydevnmmyr ua ble fwhcil ybx wbh dj Dfurm rbrs wal Kgmfg us Wxmvtqrf. Bab D gmifx hrrni knog Rgrikr kuv qhbfi jr de hnvl. Yy fudaiahd n grdwr thnwyf sa lzsgryf iidl aofnj rb tolikoq_prwark(), obg ufil tmstksqrd ms nsadm qe nv P lrg rcqiyrh xfs gegqgam enptvabt. O uenxzrm teahjzh rvy xdbv os vthre mlxaqqc, zvaa brz sw zvr Rgxyet kvlrddf vksmxvw "avgbh v-b DGHUFCU DYSP." W ntzcq skieobt ghw dmuf, pxu gx fljykkr ng mx: "Tpcmtawibq kyebcr." C ahws "vk -t xsba" olh utu qflc gnr qvxyyqv ouotymlu.
C lpa hzwgkfngewc ypcg wva Rtkzvk izbaej, vht jcia iohqg qqwved cog sa fikogu, bqckyqs C'o r AF qvnfx oaq I kir gh ab ecwx egp ugm. Fhdwiywy, T aew bql iw Xeuyza'g rpmbyw edb bszg apw zoyrjet. M hawpxle wkilsx nwr hjsi tskg tz qx ybx vhacciy meywqr, biyntywht d svjk sx vvegsz. Oyo xykb V gudnoh kmmgcd nvjyej oaq surcgasg.
"Xcppshi ku al bfymnp." Eroirg hjbfxb. "Mic'cs bebs cx fx tyv. L vhv lwzy zueo cfa vnie g ojsb uluhc sa xyk thadlqxlhuog ks pshqftzl-hsvx fowhqnue grrpk eew cbpvvjrdkbgf, pmrdmaifcijl skie-ychecw tmuzg ojiiyc os sk ifrd br fappz-hiilzcfg acgxbhtv qqcials asxkzmk."
A kuoztzvvj oaq bgkfib whnd glz gfxbre oq lbq cziwyr.
"Lsp qre pr joexrrzba urw lrx kgx yxps. C pvzekkr n fyybypgq fkei oioavkb zntzsao 6229 obg nw ssjdgv nser ig Iyriymirvqn PZ. B uohb fcj xm yhsj cvyx L pvv'l ziez lsp. M ngg zrrktt xcgncct cjy."
Z miyceo egb ziryaq vros yog rlej. "Lraczs?"
"Lhs..." Rjjijx ixnzcrh, "Dr wgqg, V bdoekfh sql frvz mezc zl oxfgis hr bqo lsp sek jrey bqazreirt dxlmkbmb."
"Qphh?" X wrinxrasb.
Ijzlzl dsntrh wetq wa uiy kcegf, mgxymik. "Pui fre, qsk rvy soog fiqiigz lraim V hrjy ohea exmdhzge ij n xzed ut uvgtli gydudcc vrymmorhnlk, olkg hkbr gnr vrkoqvcami qzrpqkn pbiyilcqozphn xffyegb tpsp isiuwg fapl vw LYQ nad ybjt rvyg. X hwz xyk qynsd GL35J wh rfzre xj wfxh gurfoth rzf bi UPOD'w mruxpulnhpekk QF ftgdorrg, upu dvry xyk cars oirn hvh qmxrromrr hb wobr esid tiatxl iw vwpyz osgscg."
"Nlnc'g... Rldm'z qehcfyvfgi..." Z yovq.
"Yuc kvmpuval lvzvt'h erawmscr cw mag," Rkbiiz skclrcaeu, "pog zhvoh vmreblu ujet jiua zr yau gips udcc gs pxzrwmr a eujzwhxec ss pdrld qbzmtrod iy wvdru ai vlaojm tm lvyhb. Hb hcs yqwlzkloaj jlvx knog zegvn?"
"Yf...." W muxq, vzeconvag tx pyg kxwpr fxmeems V jaj uolv hi ihrodopq mevybnnxz kea qbeegtspq, "m-sgrf, V kpijy...?"
Sttejt egnsg tm hrikpp obgb mr wzfl T nilg dz cw ac vul yic xfs wszvolh whw wf em vtgimrrr cetata. "Esgb gy, pah osxkhurr hi pgzf finir hjae zvr joifq."
sfilph: hgwsw://oan.kcrxvx.xsd/x/ipya/oowqcbnu/s2b4md/hc_vddreiwnak_kwwi_rlr_gn35p_wobny/'''

alpha = ascii_uppercase
vigenere_square = []
for i in range(26):
    row = alpha[i:] + alpha[:i]
    vigenere_square.append(list(row))

key = ""
known_plaintext_part = "lactf{"
ciphertext_part = ciphertext[:len(intro)]

for i in range(len(intro)):
    ciphertext[i],intro[i]
    for j in range(161):
        if vigenere_square[alpha.find(known_plaintext_part[i])][j] == ciphertext_part[i]:
            key = key[:j] + known_plaintext_part[i] + key[j+1:]
