#-*-coding:utf-8-*- #编码声明，不要忘记！
import requests
import json
import time
import mailhelper
import thread
import math
import random
from PIL import Image
from StringIO import StringIO

from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

import rsa
import binascii
import base64

mailto = ['17538006@qq.com','florashine@163.com',]
#mailto = ['17538006@qq.com',]

"""
var e=window.CryptoJS.MD5(this.password).toString();
window.HDEncryptor.doAsyncEncrypt(e,function(e,o){n.i(s.e)({byTpk:o,byKek:e,phoneNumber:t.account,captchaCode:t.captchaCode,captchaToken:t.captchaToken}).then(function(e){e.success?t.$emit("loginSuccess",e):"040205"===e.code?t.$emit("lockAccount",t.account,t.clearData):(t.$emit("loginFailed"),"369997"===e.code?(t.captchaToken&&t.$toast(e.msg),t.fetchCaptcha()):t.$toast(e.msg||e.resultMsg||"登录失败，请重试"))}).catch(function(){t.$emit("loginFailed")})},function(e){t.$emit("loginFailed"),t.$toast(e.resultMsg||e.msg||"登录失败，请重试")})}},gotoRegister:function(){if(this.isUsercenter)return void this.$router.push({name:"register"});location.href="/usercenter/register?returnURL="+encodeURIComponent(/[^?]+/.exec(document.location.href)[0])}}}},1267:function(t,e,n){var o=n(1012);"string"==typeof o&&(o=[[t.i,o,""]]),o.locals&&(t.exports=o.locals);n(4)("4b0f9480",o,!0)},127:function(t,e,n){e=t.exports=n(3)(void 0),e.push([t.i,".input-3j-TE_0{margin-bottom:22px}.link-2zZL0_0{color:#3289ef;cursor:pointer}.link-2zZL0_0:hover{color:#3289ef;text-decoration:underline}.loginBtn-1mvES_0{width:100%;margin:20px 0}.captcha-FBlSj_0{margin-bottom:20px;position:relative}.captcha-FBlSj_0>img{position:absolute;top:0;right:0;height:100%;cursor:pointer}",""]),e.locals={input:"input-3j-TE_0",link:"link-2zZL0_0",loginBtn:"loginBtn-1mvES_0",captcha:"captcha-FBlSj_0"}},128:function(t,e,n){function o(t){this.$style=n(130)}var r=n(2)(n(126),n(129),o,null,null);t.exports=r.exports},129:function(t,e){t.exports={render:function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",[n("HdInput",{class:t.$style.input,attrs:{value:t.account,errMsg:t.accountErr,maxlength:"11",placeholder:"请输入手机账号",iconName:"icon-modal-account"},on:{onChange:t.accountChange,blur:t.validAccount}}),t._v(" "),n("HdInput",{class:t.$style.input,attrs:{value:t.password,type:"password",errMsg:t.passwordErr,placeholder:"请输入登录密码",iconName:"icon-modal-password"},on:{onChange:t.passwordChange,blur:t.validPassword,onPressEnter:t.login}}),t._v(" "),t.captchaToken?n("div",{class:t.$style.captcha},[n("HdInput",{attrs:{iconName:"icon-captcha",value:t.captchaCode,placeholder:"请输入图片验证码"},on:{onChange:t.captchaChange,onPressEnter:t.login}}),t._v(" "),n("img",{attrs:{src:t.imgSrc,alt:"验证码"},on:{click:t.fetchCaptcha}})],1):t._e(),t._v(" "),n("a",{class:t.$style.link,staticStyle:{float:"right"},attrs:{href:"javascript:;"},on:{click:t.gotoForgetPwd}},[t._v("忘记密码")]),t._v(" "),n("HdButton",{class:["hd-btn hd-btn-confirm",t.$style.loginBtn],on:{click:t.login}},[t._v(t._s(t.loginStatus))]),t._v(" "),n("div",{staticStyle:{"text-align":"center"}},[t._v("\n    没有账号？现在就"),n("span",{class:t.$style.link,on:{click:t.gotoRegister}},[t._v("立即注册")])])],1)},staticRenderFns:[]}},130:function(t,e,n){var o=n(127);"string"==typeof o&&(o=[[t.i,o,""]]),o.locals&&(t.exports=o.locals);n(4)("346e0958",o,!0)},24:function(t,e,n){"use strict"

https://www.hdfax.com/product/cashier/2/90207247

https://www.hdfax.com/order/create
{productId=90207512&orderAmount=55172.05&couponCode=&paymentInstrumentType=6}

return:
{orderNo: "18021010295829206614", success: true, useCustMsg: false, resultCode: "1000",…}
orderNo:"18021010295829206614"
resultCode:"1000"
resultMsg:"成功"
success:true
traceNo:"mtp0a0800cf42173080033"
useCustMsg:false


https://www.hdfax.com/encryption/getTpSecurityKeys
return:
kek:"308189028181009fa6334baf70c3361632221023e28ae6821ff762b9c1e30f07bb8140aaee181943f53a3417b8d240940c52ca5afe8b032dc17cffab331656f24d6a10ac83dd42bf57eec742e6b1062e55100860405b3ea4f03e8ad32aee86ee8d1c650fa02911f59f556dc95f2c7f05ce05a40f7b4b523e2b8c1be7a8d97591aab421237438730203010001"
resultCode:"1000"
resultMsg:"成功"
success:false
timestamp:"1518229884163"
tpk:"30818902818100ccd601e07aeffc7f5f6d20d841d75d7883d13cd0ea6a5557cd54b413a203e8fa6ea330e5d556fc8f0f22ef352969ac03153475dc9ce3cddd58a2a4e8ca373eac1811562eeec03a2ced54697a699f68de44aedb65bb49ec4acf4bdf502764a2a6e35bc539d66c373c5274f713cd72b97c0dd7b94b2791a82aa51fd5ddef3e0e850203010001"
traceNo:"mtp0a01009742173083666"
useCustMsg:false


https://www.hdfax.com/order/pay
byKek:11424f189ff10e41b7fc95ac894976ee18dc5740408b3ec94e9015415196caf8646ff4b9b52f18606d082be1063047b2e9c1d45a49974dd17ba8754d92a669f322b48845d7a2d0e5eb4e7c03d06acb41048c91025233fefdb1abdef07f78aaed06a8c71e97aab4ba057432e768b5ad6f536e0c777b34921c22e90e36a8c1c7e8
byTpk:54be7454e86103b743f44fd417c2380b7b642ba63e8d4f913539a61d8b119ebc16e5ce593203026e9b17c06eb306bd200ad98bf0a458d3c5712d75bea0600c9260d60ede01428a0ef2aff27925b98a3d9c785b00dcc75adfc659bbbee6dc96086ac605eec4477cc9863195785ef62d47a13ad5cc77992d1daf04e30fb0a2fb6e7cba916bccc0186c5df29def88
orderNo:18021010295829206614
couponCode:
paymentInstrumentType:6

return:
resultCode:"360214"
resultMsg:"该笔转让已由其他用户成交，交易失败。"
success:false
traceNo:"mtp0a0800cf42173083631"
useCustMsg:false
"""

header = { "User-Agent" : "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.13 Safari/537.36",
            "Host": "www.hdfax.com",
           "Referer": "https://www.hdfax.com/"
           }
def randomByte():
    b = 0;
    for i in range(0,8):
        selector = 1 if random.random() > 0.5 else 0
        b += selector * math.pow(2, i)
    return int(b);

def generateK3():
    ary = []
    for i in range(0,8):
        ary.append(chr(randomByte()))
    return ''.join(ary)

def extractModulus(hexPubKey):
    if len(hexPubKey) != 280:
        return None
	
    modulus = hexPubKey[14:270]
    return modulus

def extractExp(hexPublicKey):
    if len(hexPublicKey) != 280:
        return None

    return hexPublicKey[-6:]

def doRsa(secret, k):
    hexKey = k
    modulus = int(extractModulus(hexKey),16)
    e = int(extractExp(hexKey),16)
    key = rsa.PublicKey(modulus, e) #创建公钥
    encrypt = rsa.encrypt(secret, key)
    return encrypt

def initKey(aKey):
    state = []
    for i in range(0,256):
        state.append(i)
    index1 = 0;
    index2 = 0;
    if aKey == None:
        return None
    for i in range(0,256):
        index2 = ((ord(aKey[index1]) & 0xff) + state[i] + index2) & 0xff
	tmp = state[i]
	state[i] = state[index2]
	state[index2] = tmp
	index1 = (index1 + 1) % len(aKey)
    return state

def RC4Base(text, mkey):
    x = 0
    y = 0
    skey = initKey(mkey)
    xorIndex = 0
    result = ''
    for i in range(0, len(text)):
        x = (x + 1) & 0xff
	y = ((skey[x] & 0xff) + y) & 0xff
	tmp = skey[x]
	skey[x] = skey[y]
	skey[y] = tmp
	xorIndex = ((skey[x] & 0xff) + (skey[y] & 0xff)) & 0xff
	result += chr((ord(text[i]) ^ skey[xorIndex]) & 0xff)
    return result

def doRC4(secret, k):
    ret = RC4Base(secret, k)
    return ret

def mergeTs(e2, ts):
    return ts + e2;

def makeLoginParams(json):
    h = MD5.new()
    h.update(b'jiang3893')
    secret = h.hexdigest()

    k1 = str(json['kek'])
    k2 = str(json['tpk'])
    ts = str(json['timestamp'])
    k3 = generateK3()

    e2 = doRsa(secret, k2) # 128
    e2ts = mergeTs(e2, ts)  #141
    e3 = doRC4(e2ts, k3)
    e1 = doRsa(k3, k1)

    byKek = binascii.b2a_hex(e1)
    byTpk = binascii.b2a_hex(e3)
    return {'byKek':byKek,'byTpk':byTpk}
    

def fetchHdFax(yieldrate, days):
    print("HDFax thread up")
    records = {}
    index = 1
    while 1:
        try:
            page = requests.get('https://www.hdfax.com/myasset/overview')
            if page.status_code >= 300:
                print("request status error: "+page.status_code)
                continue
            print(page.text)
        except:
            pass

def getLoginData():
    page = requests.post('https://www.hdfax.com/encryption/getTpSecurityKeys')
    loginKeys = makeLoginParams(page.json())
    loginData = {
            'byTpk':loginKeys['byTpk'],
            'byKek':loginKeys['byKek'],
            'phoneNumber':'18671403888',
            'captchaCode':'',
            'captchaToken':''
            }
    page = requests.post('https://www.hdfax.com/user/hasLoginPwd',{'phoneNumber':'18671403888'})
    return loginData

def main():
    #testdata()
    #return
    #thread.start_new_thread(fetchHdFax, (6.0, 65))
    s = requests.session()  
    
    loginData = getLoginData()
    response = s.post('https://www.hdfax.com/user/login', loginData, headers=header)
    loginRet = response.json()
    print(loginRet)
    while not loginRet['success']:
        print(loginRet['msg'])
        imgData = s.get('https://www.hdfax.com/captcha/apply')
        imgJson = imgData.json()
        data = base64.b64decode(imgJson['applyPicCaptchaResponse']['captcha'])
        image = Image.open(StringIO(data))
        img_L = image.convert("L")
        for y in range(0,img_L.size[1]):
            line = ""
            for x in range(0,img_L.size[0]):
                pix = img_L.getpixel((x,y))
                if pix < 160:
                    line += '*'
                else:
                    line += ' '
            if line.find('*') > 0:
                print(line)

        captchacode = raw_input('captcha code:')
        loginData = getLoginData()
        loginData['captchaCode'] = captchacode
        loginData['captchaToken'] = imgJson['applyPicCaptchaResponse']['captchaToken']
        print(loginData)
        response = s.post('https://www.hdfax.com/user/login', loginData, headers=header)
        loginRet = response.json()
        print(loginRet)

    page = s.post('https://www.hdfax.com/user/isLoginMtp', {'useCusMsg':0}, headers=header)
    print(page.text)
    page = s.post('https://www.hdfax.com/myasset/overview', headers=header)
    print(page.text)

    #page = requests.get('https://www.hdfax.com/product/cashier/2/90207247')
    #print(page.text)

main()
