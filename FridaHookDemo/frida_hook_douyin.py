import frida
import sys

device = "127.0.0.1:21513"
rdev = frida.get_device(device)
session = rdev.attach("com.ss.android.ugc.aweme")

scr = """
Java.perform(function () {

//********************************hook java***********************************//
var utils = Java.use("com.ss.android.common.applog.k");
var clazz = Java.use('java.lang.Class');
var Exception = Java.use("java.lang.Exception");

var cms = Java.use("com.ss.sys.ces.a");

var stringBuilder = Java.use('java.lang.StringBuilder');

//hook overload method
utils.a.overload("java.lang.String").implementation = function(){
	//get args after change result value
	send("get args after change result value 1111 ********  ");
    var arg = arguments[0];

    send("before arg 1111 :"+arg);
    var ret=this.a(arg);

    var resultstr=Bytes2HexString(ret);
    send("result Bytes2HexString 1111 :"+resultstr);

	send("+++++++++++++++ result value 1111 ********  ");

    return  ret;
};

utils.a.overload("[B").implementation = function(){
	//get args after change result value
	send("get args after change result value 000 ********  ");
    var intary = arguments[0];
	//for(var i=0;i<intary.length;i++){
    	//send("hex:"+intary[i].toString(16));
   // }
    var resultstr=Bytes2HexString(intary);
    send(" init intary result:"+resultstr);

    var ret=this.a(intary);

     send("result arg 0000 :"+ret);

    send("999999999999999 result value 000 ********  ");
    return ret;
};


cms.leviathan.overload("int","[B").implementation = function () {

    send("6666666666666666 result value 000 ********  ");
    
    
    var v1 = arguments[0];
    var v2 = arguments[1];
    send("leviathan v1 :"+v1);
    var array=Bytes2HexString(v2);
    send(" leviathan v2 :"+array);
    
  //  return this.leviathan(v1,v2);
    var ret=new Array()
     ret = this.leviathan(v1,v2);
    var resultstr=Bytes2HexString(ret);
    send(" leviathan result  intary result:"+resultstr);
    send("6666666666666666 result value 1111 ********  ");
    
    
    
    
    
  //  var hexString="ACDE74A94E6B493A3399FAC83C7C08B35D58B21D9582AF77647FC9902E36AE70F9C001E9334E6E94916682224FBE4E5F00000000000000000000000000000000";
  //  var currentTimeMillis2="1562848170";
  //  var b = parseInt(currentTimeMillis2);
    
  //  var tt=[]
  //   tt=HexString2Bytes(hexString);
  //   send(" leviathan result  rr  000000000 ******************* tt result:"+Bytes2HexString(tt));
     
    var r=new Array()
    r = this.leviathan(v1, v2);
    send(" leviathan result  rr 111111111*******************  result: 0000000000000 --- -"+v1);
    var rr=Bytes2HexString(r);
    send(v1+" leviathan result  rr  2222222222 *******************  result:"+rr);
     send(v1+" leviathan result  rr 2222222222 *******************  v2:"+array);
    
    
    return ret;
}

function hexToBytes(hex) {
    var bytes = [];
    for ( c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

//stringBuilder.toString.implementation = function () {
  //  var ret = this.toString();
  //  send("stringBuilder toString :"+ret);
  //  return ret;
//}



//****************************************************************************//

//********************************hook native before *********************************//
//hook unexport function 


var soAddr = Module.findBaseAddress("libcms.so");
send('base soAddr: ' + soAddr);
var sha1InputAddr = soAddr.add(0x75A5C+1);
send('hook soAddr: ' + sha1InputAddr);

//var nativePointer = new NativePointer(sha1InputAddr‬);
//send("net native pointers:"+nativePointer);

//var result_pointer;
intercept(sha1InputAddr);


//********************************hook native  end *********************************//

//hook export function

function intercept(address) {
    try {
        Interceptor.attach(address, {
              onEnter: function(args) {     
        var v3 = args[2].toInt32();   //时间
    	var v4 = args[3].toInt32();   

    	send("***************** netcrypt before 时间  so args:  "+v3+",  -----   "+v4);
      //  var buffer = Memory.readByteArray(args[3], 100);
     //   var resultstr=Bytes2HexString(buffer);
        
      //  send(" ********netcrypt  before:"+resultstr);
        
    },

    onLeave:function(retval){
        // send("***************** netcrypt  so result value:  end ****************   "+retval.toInt32()); 
         
       //         var ret=Memory.readCString(retval);
         
         
       //   var arybuffer = Memory.readByteArray(ret, 16);
       //    var resultstr=Bytes2HexString(arybuffer);
        //  send("***************** netcrypt   init intary result:"+resultstr);
    
         send("***************** netcrypt  onLeave:function result value  ********  ");
       }
    });
    } catch (e) {
        console.error(e);
    }
}

//十六进制字符串转字节数组，跟网上demo一样
function HexString2Bytes(str) {
  var pos = 0;
  var len = str.length;
  if (len % 2 != 0) {
    return null;
  }
  len /= 2;
  var arrBytes = new Array();
  for (var i = 0; i < len; i++) {
    var s = str.substr(pos, 2);
    var v = parseInt(s, 16);
    arrBytes.push(v);
    pos += 2;
  }
  return arrBytes;
}

//字节数组转十六进制字符串，对负值填坑
function Bytes2HexString(arrBytes) {
  var str = "";
  for (var i = 0; i < arrBytes.length; i++) {
    var tmp;
    var num=arrBytes[i];
    if (num < 0) {
    //此处填坑，当byte因为符合位导致数值为负时候，需要对数据进行处理
      tmp =(255+num+1).toString(16);
    } else {
      tmp = num.toString(16);
    }
    if (tmp.length == 1) {
      tmp = "0" + tmp;
    }
    str += tmp;
  }
  return str;
}




//****************************************************************************//

});
"""

script = session.create_script(scr)
def on_message(message ,data):
    print (message)
script.on("message" , on_message)
script.load()
sys.stdin.read()