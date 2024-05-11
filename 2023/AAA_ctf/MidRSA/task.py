from secret import flag
from Crypto.Util.number import *


def genKey(nbits, dbits):
    bbits = (nbits // 2 - dbits) // 2

    while True:
        a = getRandomNBitInteger(dbits)
        b = getRandomNBitInteger(bbits)
        c = getRandomNBitInteger(bbits)
        p1 = a * b * c + 1
        if isPrime(p1):
            # print("p1 =", p1)
            break

    while True:
        d = getRandomNBitInteger(dbits)
        p2 = b * c * d + 1
        if isPrime(p2):
            # print("p2 =", p2)
            break

    while True:
        e = getRandomNBitInteger(bbits)
        f = getRandomNBitInteger(bbits)
        q1 = e * d * f + 1
        p3 = a * e * f + 1
        if isPrime(q1) and isPrime(p3):
            # print("p3 =", p3)
            # print("q1 =", q1)
            break

    while True:
        d_ = getRandomNBitInteger(dbits)
        if GCD(a * b * c * d * e * f, d_) != 1:
            continue
        e_ = inverse(d_, a * b * c * d * e * f)
        k1 = (e_ * d_ - 1) // (a * b * c * d * e * f)
        assert e_ * d_ == (a * b * c * d * e * f) * k1 + 1
        q2 = k1 * e * f + 1
        q3 = k1 * b * c + 1
        if isPrime(q2) and isPrime(q3):
            # print("q2 =", q2)
            # print("q3 =", q3)
            # print("e =", e_)
            print("d =", d_)
            break

    n1 = p1 * q1
    n2 = p2 * q2
    n3 = p3 * q3
    
    assert pow(pow(0xdeadbeef, e_, n1), d_, n1) == 0xdeadbeef
    assert pow(pow(0xdeadbeef, e_, n2), d_, n2) == 0xdeadbeef
    assert pow(pow(0xdeadbeef, e_, n3), d_, n3) == 0xdeadbeef

    return(e_, n1, n2, n3)


nbits = 0x600
dbits = 0x240

m = bytes_to_long(flag)
e, n1, n2, n3 = genKey(nbits, dbits)
c = pow(m, e, n1)

print("c =", c)
print("e =", e)
print("n1 =", n1)
print("n2 =", n2)
print("n3 =", n3)


# c = 598823083137858565473505718525815255620672892612784824187302545127574115000325539999824374357957135208478070797113625659118825530731575573239221853507638809719397849963861367352055486212696958923800593172417262351719477530809870735637329898331854130533160020420263724619225174940214193740379571953951059401685115164634005411478583529751890781498407518739069969017597521632392997743956791839564573371955246955738575593780508817401390102856295102225132502636316844
# e = 334726528702628887205076146544909357751287869200972341824248480332256143541098971600873722567713812425364296038771650383962046800505086167635487091757206238206029361844181642521606953049529231154613145553220809927001722518303114599682529196697410089598230645579658906203453435640824934159645602447676974027474924465177723434855318446073578465621382859962701578350462059764095163424218813852195709023435581237538699769359084386399099644884006684995755938605201771
# n1 = 621786427956510577894657745225233425730501124908354697121702414978035232119311662357181409283130180887720760732555757426221953950475736078765267856308595870951635246720750862259255389006679454647170476427262240270915881126875224574474706572728931213060252787326765271752969318854360970801540289807965575654629288558728966771231501959974533484678236051025940684114262451777094234017210230731492336480895879764397821363102224085859281971513276968559080593778873231
# n2 = 335133378611627373902246132362791381335635839627660359611198202073307340179794138179041524058800936207811546752188713855950891460382258433727589232119735602364790267515558352318957355100518427499530387075144776790492766973547088838586041648900788325902589777445641895775357091753360428198189998860317775077739054298868885308909495601041757108114540069950359802851809227248145281594107487276003206931533768902437356652676341735882783415106786497390475670647453821
# n3 = 220290953009399899705676642623181513318918775662713704923101352853965768389363281894663344270979715555659079125651553079702318700200824118622766698792556506368153467944348604006011828780474050012010677204862020009069971864222175380878120025727369117819196954091417740367068284457817961773989542151049465711430065838517386380261817772422927774945414543880659243592749932727798690742051285364898081188510009069286094647222933710799481899960520270189522155672272451