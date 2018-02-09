#-*-coding:utf-8-*- #编码声明，不要忘记！
import requests
import json
import time
import mailhelper
import thread
import math
import random
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Cipher import ARC4
import rsa
import binascii

mailto = ['17538006@qq.com','florashine@163.com',]
#mailto = ['17538006@qq.com',]

"""
var e=window.CryptoJS.MD5(this.password).toString();
window.HDEncryptor.doAsyncEncrypt(e,function(e,o){n.i(s.e)({byTpk:o,byKek:e,phoneNumber:t.account,captchaCode:t.captchaCode,captchaToken:t.captchaToken}).then(function(e){e.success?t.$emit("loginSuccess",e):"040205"===e.code?t.$emit("lockAccount",t.account,t.clearData):(t.$emit("loginFailed"),"369997"===e.code?(t.captchaToken&&t.$toast(e.msg),t.fetchCaptcha()):t.$toast(e.msg||e.resultMsg||"登录失败，请重试"))}).catch(function(){t.$emit("loginFailed")})},function(e){t.$emit("loginFailed"),t.$toast(e.resultMsg||e.msg||"登录失败，请重试")})}},gotoRegister:function(){if(this.isUsercenter)return void this.$router.push({name:"register"});location.href="/usercenter/register?returnURL="+encodeURIComponent(/[^?]+/.exec(document.location.href)[0])}}}},1267:function(t,e,n){var o=n(1012);"string"==typeof o&&(o=[[t.i,o,""]]),o.locals&&(t.exports=o.locals);n(4)("4b0f9480",o,!0)},127:function(t,e,n){e=t.exports=n(3)(void 0),e.push([t.i,".input-3j-TE_0{margin-bottom:22px}.link-2zZL0_0{color:#3289ef;cursor:pointer}.link-2zZL0_0:hover{color:#3289ef;text-decoration:underline}.loginBtn-1mvES_0{width:100%;margin:20px 0}.captcha-FBlSj_0{margin-bottom:20px;position:relative}.captcha-FBlSj_0>img{position:absolute;top:0;right:0;height:100%;cursor:pointer}",""]),e.locals={input:"input-3j-TE_0",link:"link-2zZL0_0",loginBtn:"loginBtn-1mvES_0",captcha:"captcha-FBlSj_0"}},128:function(t,e,n){function o(t){this.$style=n(130)}var r=n(2)(n(126),n(129),o,null,null);t.exports=r.exports},129:function(t,e){t.exports={render:function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",[n("HdInput",{class:t.$style.input,attrs:{value:t.account,errMsg:t.accountErr,maxlength:"11",placeholder:"请输入手机账号",iconName:"icon-modal-account"},on:{onChange:t.accountChange,blur:t.validAccount}}),t._v(" "),n("HdInput",{class:t.$style.input,attrs:{value:t.password,type:"password",errMsg:t.passwordErr,placeholder:"请输入登录密码",iconName:"icon-modal-password"},on:{onChange:t.passwordChange,blur:t.validPassword,onPressEnter:t.login}}),t._v(" "),t.captchaToken?n("div",{class:t.$style.captcha},[n("HdInput",{attrs:{iconName:"icon-captcha",value:t.captchaCode,placeholder:"请输入图片验证码"},on:{onChange:t.captchaChange,onPressEnter:t.login}}),t._v(" "),n("img",{attrs:{src:t.imgSrc,alt:"验证码"},on:{click:t.fetchCaptcha}})],1):t._e(),t._v(" "),n("a",{class:t.$style.link,staticStyle:{float:"right"},attrs:{href:"javascript:;"},on:{click:t.gotoForgetPwd}},[t._v("忘记密码")]),t._v(" "),n("HdButton",{class:["hd-btn hd-btn-confirm",t.$style.loginBtn],on:{click:t.login}},[t._v(t._s(t.loginStatus))]),t._v(" "),n("div",{staticStyle:{"text-align":"center"}},[t._v("\n    没有账号？现在就"),n("span",{class:t.$style.link,on:{click:t.gotoRegister}},[t._v("立即注册")])])],1)},staticRenderFns:[]}},130:function(t,e,n){var o=n(127);"string"==typeof o&&(o=[[t.i,o,""]]),o.locals&&(t.exports=o.locals);n(4)("346e0958",o,!0)},24:function(t,e,n){"use strict"

https://www.hdfax.com/product/cashier/2/90207247
"""

head = {
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
	
    modulus = hexPubKey[14:256]
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
    ret = binascii.b2a_hex(rsa.encrypt(secret, key))
    return ret
    
    #rsa = RSA.construct((modulus, e))
    #return rsa.encrypt(secret)

def initKey(aKey):
    state = []
    for i in range(0,256):
        state.append(i & 0xff)
    index1 = 0;
    index2 = 0;
    if aKey == None:
        return None
    for i in range(0,256):
        index2 = ((ord(aKey[index1]) & 0xff) + (state[i] & 0xff) + index2) & 0xff
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
    reth = binascii.b2a_hex(ret)
    return reth

def mergeTs(e2, ts):
    return ts + e2;

def makeLoginParams(json):
    h = MD5.new()
    h.update(b'jiang3893')
    secret = h.hexdigest()

    k1 = json['kek']
    k2 = json['tpk']
    ts = json['timestamp']
    k3 = generateK3()

    e2 = doRsa(secret, k2)
    e2ts = mergeTs(e2, ts)
    e3 = doRC4(e2ts, k3)
    e1 = doRsa(k3, k1)
    print(e1,e3)

    byKek = e1
    byTpk = e3
    return ['','']
    

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

def main():
    #thread.start_new_thread(fetchHdFax, (6.0, 65))
    page = requests.post('https://www.hdfax.com/encryption/getTpSecurityKeys')
    makeLoginParams(page.json())
    
    page = requests.post('https://www.hdfax.com/user/hasLoginPwd',{'phoneNumber':'18671403888'})
    print(page.text)
    loginData = {
            'byTpk':'',
            'byKek':'',
            'phoneNumber':'18671403888',
            'captchaCode':'',
            'captchaToken':''
            }
    page = requests.post('https://www.hdfax.com/user/login', loginData)
    print(page.text)

    #page = requests.get('https://www.hdfax.com/product/cashier/2/90207247')
    #print(page.text)
    
        

main()
