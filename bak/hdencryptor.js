function str2hex(str){
	var ret = "";
	for(var i = 0; i < str.length; i ++){
		var c = str.charCodeAt(i).toString(16);
		if(c.length < 2)
			c = "0" + c;
		ret += c;
	}
	
	return ret;
}

function ary2Str(ary){
	return String.fromCharCode.apply(null,ary);
}

function hex2Str(strInHex){
	if(strInHex.length % 2 != 0)
		return null;

	var loop = strInHex.length / 2;

	var ary = new Array();

	for(var i = 0; i < loop; i ++){
		var hex = strInHex.substr(i * 2, 2);
		ary.push(parseInt(hex, 16));
	}

	return ary2Str(ary);
}

function ary2Hex(ary){
	var ret = "";
	
	for(var i = 0; i < ary.length; i ++){
		var c = ary[i].toString(16);
		if(c.length < 2)
			c = "0" + c;
		ret += c;
	}
	
	return ret;
}

function extractModulus(hexPubKey){
	if(hexPubKey.length != 280)
		return null;
	
	var modulus = hexPubKey.substr(14, 256);
	return modulus;
}

function extractExp(hexPublicKey){
	if(hexPublicKey.length != 280)
		return null;

	return hexPublicKey.substr(-6);
}

function initKey(aKey) {
		var state = new Array(); 

		for (var i = 0; i < 256; i++) {
			state[i] = i & 0xff;
		}
		var index1 = 0;
		var index2 = 0;
		if (!aKey) {
			return null;
		}
		for (var i = 0; i < 256; i++) {
			index2 = ((aKey.charCodeAt(index1) & 0xff) + (state[i] & 0xff) + index2) & 0xff;
			var tmp = state[i];
			state[i] = state[index2];
			state[index2] = tmp;
			index1 = (index1 + 1) % aKey.length;
		}

		return state;
}

function RC4Base(input, mkey) {
		var x = 0;
		var y = 0;
		var skey = initKey(mkey);
		var xorIndex;
	  var result = new Array(input.length);

		for (var i = 0; i < input.length; i++) {
			x = (x + 1) & 0xff;
			y = ((skey[x] & 0xff) + y) & 0xff;
			var tmp = skey[x];
			skey[x] = skey[y];
			skey[y] = tmp;
			xorIndex = ((skey[x] & 0xff) + (skey[y] & 0xff)) & 0xff;
			result[i] = (input.charCodeAt(i) ^ skey[xorIndex]) & 0xff;
		}

		return result;
}

function rc4ResultToB64(result){
	var binRet = ary2Str(result);
	return Base64.encode(binRet);
}

function strToCharCode(str){
	var ary = new Array();
	for(var i = 0; i < str.length; i ++){
		var code = str.charCodeAt(i);
		ary.push(code);
	}
	
	return ary;
}

function randomByte() {
	var b = 0;
	for(var i = 0; i < 8; i ++){
		var selector = Math.random() > 0.5 ? 1 : 0;

		b += selector * Math.pow(2, i);
	}

	return b;
}


/*Js noise added at:Tue Jan 30 2018 11:58:51 GMT+0800 (CST) */

var HDEncryptor = {};

(function(encryptor){
    function generateK3(){
        var ary = new Array();

        for(var i = 0; i < 8 ; i ++) {
            ary.push(randomByte());
        }

        return ary2Str(ary);
    }

    function doRsa(secret, k){
        var hexKey = k;
        var modulus = extractModulus(hexKey);
        var e = extractExp(hexKey);
        setMaxDigits(280);
        var kp = new RSAKeyPair(e, "", modulus, 1024);
        var ret = encryptedString(kp, secret, RSAAPP.PKCS1Padding, RSAAPP.RawEncoding);
        return ret;
    }

    function doRC4(secret, k){
        var ret = RC4Base(secret, k);
        return ary2Str(ret);
    }


    function mergeTs(e2, ts){
        return ts + e2;
    }


    function _doAsyncEncrypt(secret, cbSuccess, cbFailure, sync, cbComplete){
        var ret = true;

        $.ajax({
            url: CONFIG("root")+"encryption/getTpSecurityKeys",
            type: "POST",
            //cache: true,
            async: !sync,
            dataType: "json",
            success:function(res, status, xhr){
                ret = true;

                if(res.resultCode != "1000"){
                    cbFailure({"resultCode" : res.resultCode, "resultMsg" : res.resultMsg});
                    return;
                }

                var json = res;
                var k1 = json.kek;
                var k2 = json.tpk;
                var ts = json.timestamp;
                var k3 = generateK3();

                var e2 = doRsa(secret, k2);
                var e2ts = mergeTs(e2, ts);
                var e3 = doRC4(e2ts, k3);
                var e1 = doRsa(k3, k1);

                var byKek = str2hex(e1);
                var byTpk = str2hex(e3);

                if(sync){
                    cbSuccess(byKek, byTpk);
                }
                else {
                    //这里有可能会在回调里在做ajax,通过这种方式确保没有状态竞争
                    setTimeout(function () {
                        cbSuccess(byKek, byTpk);
                    }, 1);
                }
                return true;
            },
            error:function(res, textStatus, errorThrown){
                ret = false;

                var res = {"resultCode" : -1, "resultMsg":res};
                if(sync){
                    cbFailure(res)
                }
                else{
                    setTimeout(function(){
                        cbFailure(res);
                    }, 1);
                }
            },
            complete: function(){
                "use strict";
                if(cbComplete){
                    cbComplete();
                }
            }
        });

        if(sync)
            return ret;
    }

    encryptor.doAsyncEncrypt = _doAsyncEncrypt;
})(HDEncryptor);
/*Js noise added at:Tue Jan 30 2018 11:58:51 GMT+0800 (CST) */
