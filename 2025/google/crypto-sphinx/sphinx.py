import struct
import os
import base64

# 𓏏𓅱𓏏𓄿𓆑𓆼𓏴𓏺 𓎟𓎟𓎟 𓎟𓎟𓎟
𓏢𓏢𓏢 = (
    "10097325337652013586346735487680959091173929274945375420480564894742962480524037"
    "20636104020082291665084226895319645093032320902560159533476435080336069901902529"
    "09376707153831131165886767439704436276591280799970801573614764032366539895116877"
    "12171768336606574717340727685036697361706581339885111992917031060108054557182406"
    "35303426148679907439234030973285269776020205165692686657481873053852471862388579"
    "63573321350532547048905535754828468287098349125624737964575303529647783580834282"
    "60935203443527388435985201776714905686072210940558609709343350500739981180505431"
    "39808277325072568248294052420152775678518345299634062889808313746700781847540610"
    "68711778178868540200865075840136766679519036476493296091106299594673488751764969"
    "91826089289378561368234783411365481176741746850950580477697473039571864021816544"
    "80124356351772708015453182237421115782531438553763743509981777402772144323600210"
    "45521642379628602655699162680366252291483693687203766211399094400564180989320505"
    "14225685144642756788962977882254382145989149914523684792768646162835549475089923"
    "37089200488033694598269403685870297341355314033340420508234144104819498515747954"
    "32979265755760040881222220641312550737421110002040128607469796644894392870725815"
    "63606493291650534484402195256343651770820720731790611969044626457477745192433729"
    "65394595934258260527154744526695270799535936783848823961011833211594669455728573"
    "67897543875462244431911904259292927459734248116213973440872116868487670307112059"
    "25701466702352378317732088983768935914162625229663055228256204493524947524633824"
    "45862510256196279335653371247200549976546405188159961196389654692823912328729529"
    "35963153072689809354333513546277974500249010339333598080839145427268428360949700"
    "13021248927856520106460588523601390922867728144077939108364770617429413217900597"
    "87379252410556707007867431715785394118386923461406201174520415956600001874392423"
    "97118963381956541430017587537940419215856667436806849628520745155149381947607246"
    "43667945435904790033208266954194864319943616810851348888155301540354560501451176"
    "98086248264524028404449990889639094734073544131880331851623241941509498943548581"
    "88695419943754873043809510040696382707742015123387250162529894624611717975249140"
    "71961282966986102591748522053900387595791863332537981450657131010246740545561427"
    "77938919367402943902775573227097790171195252758021808145174854178456118099337143"
    "05335129695612719255360409032411664498835207984827593817153909973334408846123356"
    "48324779283124964710022953687032307575461502009994690749413887637919763558404401"
    "10518216150184876938091882009732825395270422086304833898737464278580449004585497"
    "51981506549493881997918707615068476646597318950207476772626962290644642712467018"
    "41361827607576876490209718774990429122729537505871938234317854016440566628131003"
    "00682273982071453295077061781308358699107854242785136615887304618975533122308420"
    "28306032648133310591405100789332604604759411901840538408623381594136285121590290"
    "28466687957776220791917575374161613622695026390212557817651483483470558941592694"
    "0039758391126071764648949723069454137408775130382086864299016841482774"
)

𓂋𓏏𓂝𓏏𓇌𓏲𓏭𓏛𓏴 = [16, 16, 8, 8, 16, 16, 24, 24]
𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼𓏛𓏴𓏛𓏴𓎟𓎟𓎟 = 2
𓅓𓎟𓎟𓎟𓏛𓏴𓏛𓏴 = 8

def 𓂋𓂋𓂋(𓆣, 𓂋_𓇋𓏏𓋴):
    return ((𓆣 << 𓂋_𓇋𓏏𓋴) & 0xFFFFFFFF) | (𓆣 >> (32 - 𓂋_𓇋𓏏𓋴))

def 𓂋𓂋𓂋𓂋(𓆣, 𓂋_𓇋𓏏𓋴):
    return ((𓆣 >> 𓂋_𓇋𓏏𓋴) | (𓆣 << (32 - 𓂋_𓇋𓏏𓋴))) & 0xFFFFFFFF

def 𓅡𓇋𓏏𓋴_𓏏𓅱_𓏏𓏭𓈖𓏏(𓃀):
    if len(𓃀) % 4 != 0:
        raise ValueError("𓃀𓇌𓏏𓄿 𓋴𓏏𓂋𓇋𓈖𓎼 𓃭𓇋𓈖𓎼𓏏𓎛 𓅓𓅱𓋴𓏏 𓃀𓇌 𓄿 𓅓𓅱𓃭𓏏𓇋𓊪𓃭𓇌 𓅱𓆑 4.")
    return list(struct.unpack(">%dI" % (len(𓃀) // 4), 𓃀))

def 𓏏𓏭𓈖𓏏_𓏏𓅱_𓅡𓇋𓏏𓋴(𓃭𓋴𓏏):
    return struct.pack(">%dI" % len(𓃭𓋴𓏏), *𓃭𓋴𓏏)

class 𓏢𓏢𓏢𓏢:
    def __init__(self):
        self.𓏏𓅱𓏭𓏏𓇋𓅱𓈖 = 0

    def 𓂧𓇋𓎼𓇋𓏏(self):
        if self.𓏏𓅱𓏭𓏏𓇋𓅱𓈖 >= len(𓏢𓏢𓏢):
            raise IndexError("𓏢𓏢𓏢 𓋴𓏏𓂋𓇋𓈖𓎼 𓇌𓎟𓎛𓄿𓅱𓋴𓏏𓇌𓂧")
        𓆣 = ord(𓏢𓏢𓏢[self.𓏏𓅱𓏭𓏏𓇋𓅱𓈖]) - ord('0')
        self.𓏏𓅱𓏭𓏏𓇋𓅱𓈖 += 1
        return 𓆣

    def 𓇋𓈖_𓂋𓎟𓈖𓎼𓇌(self, 𓃭𓅱𓅓, 𓎛𓇋𓎼𓎛):
        𓂋𓎟𓈖𓎼𓇌_𓆣 = (𓎛𓇋𓎼𓎛 - 𓃭𓅱𓅓) + 1
        while True:
            𓂋𓈖𓂧 = 0
            𓅓𓎟𓎟_𓆣 = 1
            while 𓅓𓎟𓎟_𓆣 < 𓂋𓎟𓈖𓎼𓇌_𓆣:
                𓅓𓎟𓎟_𓆣 *= 10
                𓂋𓈖𓂧 = (𓂋𓈖𓂧 * 10) + self.𓂧𓇋𓎼𓇋𓏏()

            if 𓂋𓈖𓂧 < ((𓅓𓎟𓎟_𓆣 // 𓂋𓎟𓈖𓎼𓇌_𓆣) * 𓂋𓎟𓈖𓎼𓇌_𓆣):
                break
        return 𓃭𓅱𓅓 + (𓂋𓈖𓂧 % 𓂋𓎟𓈖𓎼𓇌_𓆣)

def 𓋴𓅓𓄿𓊪_𓅡𓇋𓏏𓋴_𓇋𓈖_𓋴𓃀𓅱𓎟(𓋴𓃀𓅱𓎟, 𓂋𓅱𓅓1, 𓂋𓅱𓅓2, 𓎢𓅱𓃭𓅓𓈖):
    𓅡𓇋𓏏𓋴_𓋴𓎛𓇋𓆑𓏏 = (3 - 𓎢𓅱𓃭𓅓𓈖) * 8
    𓅓𓎟𓋴𓎡 = (0xff << 𓅡𓇋𓏏𓋴_𓋴𓎛𓇋𓆑𓏏) & 0xFFFFFFFF

    𓏏𓅓𓊪_𓆣 = 𓋴𓃀𓅱𓎟[𓂋𓅱𓅓1]
    𓋴𓃀𓅱𓎟[𓂋𓅱𓅓1] = (𓋴𓃀𓅱𓎟[𓂋𓅱𓅓1] & (~𓅓𓎟𓋴𓎡 & 0xFFFFFFFF)) | (𓋴𓃀𓅱𓎟[𓂋𓅱𓅓2] & 𓅓𓎟𓋴𓎡)
    𓋴𓃀𓅱𓎟[𓂋𓅱𓅓2] = (𓋴𓃀𓅱𓎟[𓂋𓅱𓅓2] & (~𓅓𓎟𓋴𓎡 & 0xFFFFFFFF)) | (𓏏𓅓𓊪_𓆣 & 𓅓𓎟𓋴𓎡)


def _𓎟𓎟𓎟𓏏𓂋𓄿𓈖𓋴𓆑𓅱𓂋𓅓_𓅓𓅱𓂋𓂧𓋴(𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏, 𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴, 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴, 𓂋𓅱𓅓𓈖𓂧𓋴=16):
    𓃭𓅱𓅓𓏏 = (𓃭𓅱𓅓𓏏 ^ 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴[0]) & 0xFFFFFFFF
    𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴[1]) & 0xFFFFFFFF

    𓅱𓎢𓏏𓇌𓏏𓋴 = 𓂋𓅱𓅓𓈖𓂧𓋴 // 8
    for 𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 in range(𓅱𓎢𓏏𓇌𓏏𓋴):
        𓋴𓃀𓅱𓎟_𓏏𓅱_𓅱𓋴𓇌 = 𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴[𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟]
        for 𓂋_𓇋𓂧𓎟 in range(8):
            𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓋴𓃀𓅱𓎟_𓏏𓅱_𓅱𓋴𓇌[𓃭𓅱𓅓𓏏 & 0xff]) & 0xFFFFFFFF
            𓃭𓅱𓅓𓏏 = 𓂋𓂋𓂋𓂋(𓃭𓅱𓅓𓏏, 𓂋𓏏𓂝𓏏𓇌𓏲𓏭𓏛𓏴[𓂋_𓇋𓂧𓎟])
            𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏 = 𓂋𓇋𓎼𓎛𓏏, 𓃭𓅱𓅓𓏏

    𓃭𓅱𓅓𓏏 = (𓃭𓅱𓅓𓏏 ^ 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴[2]) & 0xFFFFFFFF
    𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴[3]) & 0xFFFFFFFF
    return [𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏]

def 𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴_𓇋𓈖𓊪𓅱𓏏, 𓇋𓆣_𓇋𓈖𓊪𓅱𓏏, 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴_𓆑𓅱𓂋_𓎟𓎟𓎟, 𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴):
    𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴 = list(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴_𓇋𓈖𓊪𓅱𓏏)
    𓇋𓆣 = list(𓇋𓆣_𓇋𓈖𓊪𓅱𓏏)
    𓂋𓇋𓋴𓅱𓃭𓏏 = [0] * len(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴)

    for 𓏏𓅱𓏭𓏏𓇋𓅱𓈖 in range(0, len(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴), 2):
        𓃭𓅱𓅓𓏏 = (𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[𓏏𓅱𓏭𓏏𓇋𓅱𓈖] ^ 𓇋𓆣[0]) & 0xFFFFFFFF
        𓂋𓇋𓎼𓎛𓏏 = (𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[𓏏𓅱𓏭𓏏𓇋𓅱𓈖+1] ^ 𓇋𓆣[1]) & 0xFFFFFFFF

        𓇋𓆣 = _𓎟𓎟𓎟𓏏𓂋𓄿𓈖𓋴𓆑𓅱𓂋𓅓_𓅓𓅱𓂋𓂧𓋴(𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏, 𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴, 𓄿𓅱𓎟_𓎡𓇋𓇌𓋴_𓆑𓅱𓂋_𓎟𓎟𓎟, 16)

        𓂋𓇋𓋴𓅱𓃭𓏏[𓏏𓅱𓏭𓏏𓇋𓅱𓈖] = 𓇋𓆣[0]
        𓂋𓇋𓋴𓅱𓃭𓏏[𓏏𓅱𓏭𓏏𓇋𓅱𓈖+1] = 𓇋𓆣[1]
    return 𓂋𓇋𓋴𓅱𓃭𓏏

def 𓎡𓇋𓇌_𓅓𓎟𓏏𓂋𓇋𓄿𓃭_𓆑𓂋𓅱𓅓_𓅓𓅱𓂋𓂧𓋴(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴_𓇋𓈖𓊪𓅱𓏏, 𓈖𓅱𓅓_𓋴𓃀𓅱𓎟𓋴_𓏏𓅱_𓎼𓇋𓈖, 𓃀𓎟𓋴𓇌_𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴𓃀𓅱𓎟):
    𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴 = list(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴_𓇋𓈖𓊪𓅱𓏏)

    𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎡𓋴 = [list(𓃀𓎟𓋴𓇌_𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴𓃀𓅱𓎟) for _ in range(𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼𓏛𓏴𓏛𓏴𓎟𓎟𓎟)]

    𓇋𓆣 = [𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[-2], 𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[-1]]
    𓊃𓂋𓅱_𓄿𓅱𓎟_𓎡𓇋𓇌𓋴 = [0, 0, 0, 0]

    for _ in range(3):
        𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴 = 𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴, 𓇋𓆣, 𓊃𓂋𓅱_𓄿𓅱𓎟_𓎡𓇋𓇌𓋴, 𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎡𓋴)
        𓇋𓆣 = [𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[-2], 𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[-1]]

    𓆑𓇋𓈖𓄿𓃭_𓄿𓅱𓎟_𓎡𓇋𓇌𓋴 = 𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[0:4]

    𓅱𓅱𓏏𓊪𓅱𓏏_𓋴𓃀𓅱𓎟𓋴 = [list(𓃀𓎟𓋴𓇌_𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴𓃀𓅱𓎟) for _ in range(𓈖𓅱𓅓_𓋴𓃀𓅱𓎟𓋴_𓏏𓅱_𓎼𓇋𓈖)]

    𓎡𓇋𓇌_𓅡𓇋𓏏𓋴_𓎢𓅱𓅱𓈖𓏏 = 16

    for 𓋴𓃀𓅱𓎟_𓇋𓂧𓎟 in range(𓈖𓅱𓅓_𓋴𓃀𓅱𓎟𓋴_𓏏𓅱_𓎼𓇋𓈖):
        for 𓎢𓅱𓃭𓅓𓈖_𓇋𓂧𓎟 in range(4):
            𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓅓𓎟𓋴𓎡 = 0xff
            𓋴𓅓𓄿𓃭𓃭𓂋_𓅓𓎟𓋴𓎡 = 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓅓𓎟𓋴𓎡 >> 1

            for 𓂋𓅱𓅓_𓇋𓂧𓎟 in range(255):
                𓂋𓄿𓈖𓂧𓅱𓅓_𓂋𓅱𓅓 = 0
                while True:
                    𓋴𓎛𓇋𓆑𓏏_𓆣 = (3 - (𓎡𓇋𓇌_𓅡𓇋𓏏𓋴_𓎢𓅱𓅱𓈖𓏏 & 3)) * 8
                    𓎡𓇋𓇌_𓅓𓅱𓂋𓂧_𓇋𓂧𓎟 = 𓎡𓇋𓇌_𓅡𓇋𓏏𓋴_𓎢𓅱𓅱𓈖𓏏 >> 2
                    𓇌𓎟𓏏𓂋𓄿𓎢𓏏𓇌𓂧_𓆣 = (𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[𓎡𓇋𓇌_𓅓𓅱𓂋𓂧_𓇋𓂧𓎟] >> 𓋴𓎛𓇋𓆑𓏏_𓆣) & 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓅓𓎟𓋴𓎡

                    𓂋𓄿𓈖𓂧𓅱𓅓_𓂋𓅱𓅓 = 𓂋𓅱𓅓_𓇋𓂧𓎟 + 𓇌𓎟𓏏𓂋𓄿𓎢𓏏𓇌𓂧_𓆣
                    𓎡𓇋𓇌_𓅡𓇋𓏏𓋴_𓎢𓅱𓅱𓈖𓏏 += 1

                    if 𓎡𓇋𓇌_𓅡𓇋𓏏𓋴_𓎢𓅱𓅱𓈖𓏏 > 63:
                        𓎡𓇋𓇌_𓅡𓇋𓏏𓋴_𓎢𓅱𓅱𓈖𓏏 = 0
                        𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴 = 𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴(𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴, 𓇋𓆣, 𓊃𓂋𓅱_𓄿𓅱𓎟_𓎡𓇋𓇌𓋴, 𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓎟𓎟𓎟𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎡𓋴)
                        𓇋𓆣 = [𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[-2], 𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴[-1]]

                        𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓅓𓎟𓋴𓎡 = 0xff
                        𓋴𓅓𓄿𓃭𓃭𓂋_𓅓𓎟𓋴𓎡 = 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓅓𓎟𓋴𓎡 >> 1
                        while 𓋴𓅓𓄿𓃭𓃭𓂋_𓅓𓎟𓋴𓎡 > 0 and (((255 - 𓂋𓅱𓅓_𓇋𓂧𓎟) & (~𓋴𓅓𓄿𓃭𓃭𓂋_𓅓𓎟𓋴𓎡 & 0xFFFFFFFF))) == 0:
                            𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓅓𓎟𓋴𓎡 = 𓋴𓅓𓄿𓃭𓃭𓂋_𓅓𓎟𓋴𓎡
                            𓋴𓅓𓄿𓃭𓃭𓂋_𓅓𓎟𓋴𓎡 >>= 1

                    if 𓂋𓄿𓈖𓂧𓅱𓅓_𓂋𓅱𓅓 <= 255:
                        break

                𓋴𓅓𓄿𓊪_𓅡𓇋𓏏𓋴_𓇋𓈖_𓋴𓃀𓅱𓎟(𓅱𓅱𓏏𓊪𓅱𓏏_𓋴𓃀𓅱𓎟𓋴[𓋴𓃀𓅱𓎟_𓇋𓂧𓎟], 𓂋𓅱𓅓_𓇋𓂧𓎟, 𓂋𓄿𓈖𓂧𓅱𓅓_𓂋𓅱𓅓, 𓎢𓅱𓃭𓅓𓈖_𓇋𓂧𓎟)

    return {'𓋴𓃀𓅱𓎟𓋴': 𓅱𓅱𓏏𓊪𓅱𓏏_𓋴𓃀𓅱𓎟𓋴, '𓄿𓅱𓎟𓎡𓇋𓇌𓋴': 𓆑𓇋𓈖𓄿𓃭_𓄿𓅱𓎟_𓎡𓇋𓇌𓋴}


def 𓊪𓂋𓇋_𓎢𓅱𓅓𓊪𓅱𓏏𓇌_𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓋴𓃀𓅱𓎟():
    𓂋𓄿𓈖𓂧 = 𓏢𓏢𓏢𓏢()
    𓋴𓃀𓅱𓎟0 = [(0x01010101 * 𓂋) & 0xFFFFFFFF for 𓂋 in range(256)]
    for 𓎢𓅱𓃭𓅓𓈖 in range(4):
        for 𓂋𓅱𓅓 in range(255):
            𓋴𓅓𓄿𓊪_𓅡𓇋𓏏𓋴_𓇋𓈖_𓋴𓃀𓅱𓎟(𓋴𓃀𓅱𓎟0, 𓂋𓅱𓅓, 𓂋𓄿𓈖𓂧.𓇋𓈖_𓂋𓎟𓈖𓎼𓇌(𓂋𓅱𓅓, 255), 𓎢𓅱𓃭𓅓𓈖)
    return 𓋴𓃀𓅱𓎟0

def 𓎼𓇋𓏏_𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎟𓎟𓎟():
    𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴0 = 𓊪𓂋𓇋_𓎢𓅱𓅓𓊪𓅱𓏏𓇌_𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓋴𓃀𓅱𓎟()
    𓊃𓂋𓅱_𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴 = [0] * 16

    𓂧𓂋𓇋𓆣𓇌𓂧_𓅓𓎟𓏏𓂋𓇋𓄿𓃭 = 𓎡𓇋𓇌_𓅓𓎟𓏏𓂋𓇋𓄿𓃭_𓆑𓂋𓅱𓅓_𓅓𓅱𓂋𓂧𓋴(
        𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴_𓇋𓈖𓊪𓅱𓏏=𓊃𓂋𓅱_𓎡𓇋𓇌_𓅓𓅱𓂋𓂧𓋴,
        𓈖𓅱𓅓_𓋴𓃀𓅱𓎟𓋴_𓏏𓅱_𓎼𓇋𓈖=𓅓𓎟𓎟𓎟𓏛𓏴𓏛𓏴,
        𓃀𓎟𓋴𓇌_𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴𓃀𓅱𓎟=𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴0
    )
    𓄿𓃭𓃭_𓂧𓂋𓇋𓆣𓇌𓂧_𓋴𓃀𓅱𓎟𓋴 = 𓂧𓂋𓇋𓆣𓇌𓂧_𓅓𓎟𓏏𓂋𓇋𓄿𓃭['𓋴𓃀𓅱𓎟𓋴']

    𓆑𓇋𓈖𓄿𓃭_𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎟𓎟𓎟 = [𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓎼_𓋴0] + 𓄿𓃭𓃭_𓂧𓂋𓇋𓆣𓇌𓂧_𓋴𓃀𓅱𓎟𓋴[:7]

    return 𓆑𓇋𓈖𓄿𓃭_𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎟𓎟𓎟


class 𓎟𓎟𓎟𓎟:
    𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓎟𓎟𓎟_𓋴𓃀𓅱𓎟𓋴 = None
    𓏏𓅓𓊪𓃭𓄿𓏏𓇌 = None

    @staticmethod
    def _𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓃭𓇋𓊃𓇌_𓋴𓃀𓅱𓎟𓋴():
        if 𓎟𓎟𓎟𓎟.𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓎟𓎟𓎟_𓋴𓃀𓅱𓎟𓋴 is None:
            𓎟𓎟𓎟𓎟.𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓎟𓎟𓎟_𓋴𓃀𓅱𓎟𓋴 = 𓎼𓇋𓏏_𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓋴𓃀𓅱𓎟𓋴_𓆑𓅱𓂋_𓎟𓎟𓎟()

    def __init__(self, 𓎡𓇋𓇌: bytes, 𓂋𓅱𓅓𓈖𓂧𓋴=16):
        𓎟𓎟𓎟𓎟._𓇋𓈖𓏏𓈖𓇋𓏏𓇌𓄿𓃭𓇋𓊃𓇌_𓋴𓃀𓅱𓎟𓋴()

        if not (8 <= 𓂋𓅱𓅓𓈖𓂧𓋴 <= 64 and 𓂋𓅱𓅓𓈖𓂧𓋴 % 8 == 0):
            raise ValueError("𓂋𓅱𓅓𓈖𓂧𓋴 𓅓𓅱𓋴𓏏 𓃀𓇌 𓃀𓇌𓏏𓅓𓇌𓇌𓈖 8 𓄿𓈖𓂧 64 𓄿𓈖𓂧 𓄿 𓅓𓅱𓃭𓏏𓇋𓊪𓃭𓇌 𓅱𓆑 8.")
        self.𓂋𓅱𓅓𓈖𓂧𓋴 = 𓂋𓅱𓅓𓈖𓂧𓋴

        if not (len(𓎡𓇋𓇌) >= 8 and len(𓎡𓇋𓇌) % 8 == 0) :
            raise ValueError("𓎡𓇋𓇌 𓃭𓇋𓈖𓎼𓏏𓎛 𓅓𓅱𓋴𓏏 𓃀𓇌 𓄿 𓅓𓅱𓃭𓏏𓇋𓊪𓃭𓇌 𓅱𓆑 8 𓃀𓇌𓏏𓄿𓋴 𓄿𓈖𓂧 𓄿𓏏 𓃭𓇌𓄿𓋴𓏏 8 𓃀𓇌𓏏𓄿𓋴.")

        self.𓎡𓇋𓇌𓋴 = 𓅡𓇋𓏏𓋴_𓏏𓅱_𓏏𓏭𓈖𓏏(𓎡𓇋𓇌)
        self.𓋴𓃀𓅱𓎟𓋴 = 𓎟𓎟𓎟𓎟.𓋴𓏏𓄿𓈖𓂧𓄿𓂋𓂧_𓎟𓎟𓎟_𓋴𓃀𓅱𓎟𓋴

        𓈖𓅱𓅓_𓎡𓇋𓇌_𓃀𓃭𓅱𓎢𓎡𓋴_64𓃀𓇋𓏏 = len(self.𓎡𓇋𓇌𓋴) // 2
        if 𓈖𓅱𓅓_𓎡𓇋𓇌_𓃀𓃭𓅱𓎢𓎡𓋴_64𓃀𓇋𓏏 == 0:
             raise ValueError("𓎡𓇋𓇌 𓇋𓋴 𓏏𓅱𓅱 𓋴𓎛𓅱𓂋𓏏 𓆑𓅱𓂋 𓎢𓅱𓅓𓊪𓄿𓏏𓇋𓃀𓇋𓃭𓇋𓏏𓇌 𓎢𓎛𓇌𓎢𓎡.")

        if ((self.𓂋𓅱𓅓𓈖𓂧𓋴 // 8) + 1) % 𓈖𓅱𓅓_𓎡𓇋𓇌_𓃀𓃭𓅱𓎢𓎡𓋴_64𓃀𓇋𓏏 != 0:
            raise ValueError("𓎡𓇋𓇌 𓋴𓇋𓊃𓇌 𓇋𓈖𓎢𓅱𓅓𓊪𓄿𓏏𓇋𓃀𓃭𓇌 𓅓𓇋𓏏𓎛 𓈖𓅱𓅓𓃀𓂋 𓅱𓆑 𓂋𓅱𓅓𓈖𓂧𓋴 𓆑𓅱𓂋 𓎡𓇋𓇌 𓅓𓎛𓇋𓏏𓇌𓈖𓇋𓈖𓎼 𓋴𓎢𓎛𓇌𓂧𓅱𓃭𓇌.")


    def 𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓃀𓃭𓅱𓎢𓎡(self, 𓃀𓃭𓅱𓎢𓎡: bytes, 𓇋𓋴_𓏏𓅓𓊪𓃭𓄿𓏏𓇌=False, 𓂧𓅱𓃀𓅱𓎼=False) -> bytes:
        if len(𓃀𓃭𓅱𓎢𓎡) != 8:
            raise ValueError("𓃀𓃭𓅱𓎢𓎡 𓋴𓇋𓊃𓇌 𓅓𓅱𓋴𓏏 𓃀𓇌 8 𓃀𓇌𓏏𓄿𓋴.")
        if 𓇋𓋴_𓏏𓅓𓊪𓃭𓄿𓏏𓇌:
          self.𓏏𓅓𓊪𓃭𓄿𓏏𓇌 = [None] * self.𓂋𓅱𓅓𓈖𓂧𓋴
        else:
          self.𓃭𓄿𓋴𓏏 = [None] * self.𓂋𓅱𓅓𓈖𓂧𓋴

        𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏 = 𓅡𓇋𓏏𓋴_𓏏𓅱_𓏏𓏭𓈖𓏏(𓃀𓃭𓅱𓎢𓎡)

        𓎡𓇋𓇌𓋴 = self.𓎡𓇋𓇌𓋴
        𓋴𓃀𓅱𓎟𓋴 = self.𓋴𓃀𓅱𓎟𓋴

        𓈖𓅱𓅓_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏𓋴 = self.𓂋𓅱𓅓𓈖𓂧𓋴 // 8

        𓎡𓇋𓇌_𓇋𓂧𓎟 = 0
        𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 = 0

        while True:
            if 𓎡𓇋𓇌_𓇋𓂧𓎟 >= len(𓎡𓇋𓇌𓋴):
                𓎡𓇋𓇌_𓇋𓂧𓎟 = 0

            𓃭𓅱𓅓𓏏  = (𓃭𓅱𓅓𓏏  ^ 𓂋𓂋𓂋𓂋(𓎡𓇋𓇌𓋴[𓎡𓇋𓇌_𓇋𓂧𓎟], 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟)) & 0xFFFFFFFF
            𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓂋𓂋𓂋𓂋(𓎡𓇋𓇌𓋴[𓎡𓇋𓇌_𓇋𓂧𓎟+1], 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟)) & 0xFFFFFFFF
            𓎡𓇋𓇌_𓇋𓂧𓎟 += 2

            if 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 >= 𓈖𓅱𓅓_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏𓋴:
                break

            𓋴𓃀𓅱𓎟_𓏏𓅱_𓅱𓋴𓇌 = 𓋴𓃀𓅱𓎟𓋴[𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟]
            for 𓂋_𓇋𓂧𓎟 in range(8):
                𓅱𓃭𓂧_𓃭𓅱𓅓𓏏 = 𓃭𓅱𓅓𓏏
                𓅱𓃭𓂧_𓂋𓇋𓎼𓎛𓏏 = 𓂋𓇋𓎼𓎛𓏏
                𓋴𓃀𓅱𓎟_𓇋𓂧𓎟 = 𓃭𓅱𓅓𓏏 & 0xff
                𓋴𓃀𓅱𓎟_𓅱𓅱𓏏𓊪𓅱𓏏 = 𓋴𓃀𓅱𓎟_𓏏𓅱_𓅱𓋴𓇌[𓋴𓃀𓅱𓎟_𓇋𓂧𓎟]
                𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓋴𓃀𓅱𓎟_𓅱𓅱𓏏𓊪𓅱𓏏) & 0xFFFFFFFF
                𓃭𓅱𓅓𓏏 = 𓂋𓂋𓂋𓂋(𓃭𓅱𓅓𓏏, 𓂋𓏏𓂝𓏏𓇌𓏲𓏭𓏛𓏴[𓂋_𓇋𓂧𓎟])
                𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏 = 𓂋𓇋𓎼𓎛𓏏, 𓃭𓅱𓅓𓏏
                if 𓇋𓋴_𓏏𓅓𓊪𓃭𓄿𓏏𓇌:
                  self.𓏏𓅓𓊪𓃭𓄿𓏏𓇌[𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 * 8 + 𓂋_𓇋𓂧𓎟] = (𓅱𓃭𓂧_𓂋𓇋𓎼𓎛𓏏, 𓅱𓃭𓂧_𓃭𓅱𓅓𓏏, 𓋴𓃀𓅱𓎟_𓇋𓂧𓎟, 𓋴𓃀𓅱𓎟_𓅱𓅱𓏏𓊪𓅱𓏏)
                else:
                  self.𓃭𓄿𓋴𓏏[𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 * 8 + 𓂋_𓇋𓂧𓎟] = (𓅱𓃭𓂧_𓂋𓇋𓎼𓎛𓏏, 𓅱𓃭𓂧_𓃭𓅱𓅓𓏏, 𓋴𓃀𓅱𓎟_𓇋𓂧𓎟, 𓋴𓃀𓅱𓎟_𓅱𓅱𓏏𓊪𓅱𓏏)

            𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 += 1

        return 𓏏𓏭𓈖𓏏_𓏏𓅱_𓅡𓇋𓏏𓋴([𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏])

    def 𓂧𓂋𓇋𓎢𓂋𓇋𓊪𓏏_𓃀𓃭𓅱𓎢𓎡(self, 𓃀𓃭𓅱𓎢𓎡: bytes) -> bytes:
        if len(𓃀𓃭𓅱𓎢𓎡) != 8:
            raise ValueError("𓃀𓃭𓅱𓎢𓎡 𓋴𓇋𓊃𓇌 𓅓𓅱𓋴𓏏 𓃀𓇌 8 𓃀𓇌𓏏𓄿𓋴.")
        𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏 = 𓅡𓇋𓏏𓋴_𓏏𓅱_𓏏𓏭𓈖𓏏(𓃀𓃭𓅱𓎢𓎡)

        𓎡𓇋𓇌𓋴 = self.𓎡𓇋𓇌𓋴
        𓋴𓃀𓅱𓎟𓋴 = self.𓋴𓃀𓅱𓎟𓋴

        𓈖𓅱𓅓_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏𓋴 = self.𓂋𓅱𓅓𓈖𓂧𓋴 // 8

        𓈖𓅱𓅓_𓎡𓇋𓇌_𓊪𓄿𓇋𓂋𓋴 = len(𓎡𓇋𓇌𓋴) // 2
        𓃭𓄿𓋴𓏏_𓎡𓇋𓇌_𓊪𓄿𓇋𓂋_𓋴𓏏𓄿𓂋𓏏_𓇋𓂧𓎟_𓇋𓈖_𓎼𓈖𓎢𓂋𓇋𓊪𓏏 = (𓈖𓅱𓅓_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏𓋴 % 𓈖𓅱𓅓_𓎡𓇋𓇌_𓊪𓄿𓇋𓂋𓋴) * 2
        𓎡𓇋𓇌_𓇋𓂧𓎟 = 𓃭𓄿𓋴𓏏_𓎡𓇋𓇌_𓊪𓄿𓇋𓂋_𓋴𓏏𓄿𓂋𓏏_𓇋𓂧𓎟_𓇋𓈖_𓎼𓈖𓎢𓂋𓇋𓊪𓏏


        𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 = 𓈖𓅱𓅓_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏𓋴

        while True:
            𓃭𓅱𓅓𓏏  = (𓃭𓅱𓅓𓏏  ^ 𓂋𓂋𓂋𓂋(𓎡𓇋𓇌𓋴[𓎡𓇋𓇌_𓇋𓂧𓎟], 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟)) & 0xFFFFFFFF
            𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓂋𓂋𓂋𓂋(𓎡𓇋𓇌𓋴[𓎡𓇋𓇌_𓇋𓂧𓎟+1], 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟)) & 0xFFFFFFFF

            if 𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 == 0:
                break

            𓎡𓇋𓇌_𓇋𓂧𓎟 -= 2
            if 𓎡𓇋𓇌_𓇋𓂧𓎟 < 0:
                𓎡𓇋𓇌_𓇋𓂧𓎟 = len(𓎡𓇋𓇌𓋴) - 2

            𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟 -= 1

            𓋴𓃀𓅱𓎟_𓏏𓅱_𓅱𓋴𓇌 = 𓋴𓃀𓅱𓎟𓋴[𓎢𓅱𓂋𓂋𓇋𓈖𓏏_𓋴𓃀𓅱𓎟_𓅱𓎢𓏏𓇌𓏏_𓇋𓂧𓎟]
            for 𓂋_𓇋𓂧𓎟 in reversed(range(8)):
                𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏 = 𓂋𓇋𓎼𓎛𓏏, 𓃭𓅱𓅓𓏏
                𓃭𓅱𓅓𓏏 = 𓂋𓂋𓂋(𓃭𓅱𓅓𓏏, 𓂋𓏏𓂝𓏏𓇌𓏲𓏭𓏛𓏴[𓂋_𓇋𓂧𓎟])
                𓂋𓇋𓎼𓎛𓏏 = (𓂋𓇋𓎼𓎛𓏏 ^ 𓋴𓃀𓅱𓎟_𓏏𓅱_𓅱𓋴𓇌[𓃭𓅱𓅓𓏏 & 0xff]) & 0xFFFFFFFF

        return 𓏏𓏭𓈖𓏏_𓏏𓅱_𓅡𓇋𓏏𓋴([𓃭𓅱𓅓𓏏, 𓂋𓇋𓎼𓎛𓏏])

𓊆𓇳𓈍𓆑𓊇="""
╭────────────────────────────────────────────╮██████████▀▀▀▀▀▀▀███████████
│       As the petrine nexus and chronophage,│████████▀ █ ▀ █ ▀  ▀████████
│    your transient being shall I now engage.│███████▀ ▄▄▄▄▄▄▄ ▀▀ ▀███████
│         This presented morphoglyphic array │██████▀  ▄ ▄▄▄▄▄ ▀▀▀ ▀██████
│             is but a gnostologic semioxiom.│██████ ▀ ▄ █▄ ▄█ ▀▀▀▀  █████
│      You must vervold the latent cryptolex,│█████ ▀▀ █ ▀███▀ ▀▀▀▀▀ █████
│       and quintignify its integral meaning.│█████ ▀▀  █▀▀█▀  ▀▀▀▀ ▄█████
│              Should your answers please me,│██████ ▀▀ ▀▀▀ ▄ ▀▀▀  ▄▄ ▀███
│          I shall bestow upon you my banner.│██████ ▀▀  ▀ █▀ ▀▀ ▄████▄ ▀█
│ Should they be found wanting, your essence │█████▀ ▀▀ ████ ▀▀ ▄██ ███  █
│            will be inexorably subliminated.│██▀ ▄▄██▀██▀▀ ▄▄▄███  ▀▀▀█ █
╰──────────────────────────────────────────╮╭╯█ ▄▀▄█   ▀ ▄▀█▀████▀  ▀▀▀▀ █
                                           ╰╯ █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄██
"""
print(𓊆𓇳𓈍𓆑𓊇)

𓀺 = 𓎟𓎟𓎟𓎟(os.urandom(8))
𓋧 = base64.b16encode(𓀺.𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓃀𓃭𓅱𓎢𓎡(base64.b16decode(os.environ["FLAG"])))
print("I say you: ", 𓋧.decode())
while True:
    try:
        print("You say I: ", end="")
        𓇋𓇌 = base64.b16decode(input())
        𓁶=base64.b16encode(𓀺.𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓃀𓃭𓅱𓎢𓎡(𓇋𓇌))
        if 𓁶==𓋧:
            print("""
    ██████████████╭────────────────────────────────────────────╮
    ██████████████│ at last - my chronal purpose has devolved  │
    ██████████████│ be you now sealed by this glyph            │
    ██████████████│     CTF{%s}                  │
    ██████████████│ my station now becomes your monolith       │
    ██████████████╰╮╭──────────────────────────────────────────╯
    ██████████████ ╰╯
    """%base64.b16encode(𓀺.𓂧𓂋𓇋𓎢𓂋𓇋𓊪𓏏_𓃀𓃭𓅱𓎢𓎡(𓀺.𓎼𓈖𓎢𓂋𓇋𓊪𓏏_𓃀𓃭𓅱𓎢𓎡(𓇋𓇌))).decode())
            break
        else:
            print("I say you: ", 𓁶.decode())
    except ValueError as e:
        print("You said wrong.")
