import frida
import sys

rdev = frida.get_remote_device()
##session = rdev.attach("com.ss.android.ugc.aweme")
session = rdev.attach("com.hlm.register.hook")

scr = """
Java.perform(function () {

//********************************hook java***********************************//
var utils = Java.use("com.ss.android.common.applog.k");
var clazz = Java.use('java.lang.Class');
var Exception = Java.use("java.lang.Exception");

var cms = Java.use("com.ss.sys.ces.a");

var stringBuilder = Java.use('java.lang.StringBuilder');


//****************************************************************************//

//********************************hook native before *********************************//
//hook unexport function 


var soAddr =0;  //Module.findBaseAddress("libcms.so");
send('base soAddr: ' + soAddr);
//var sha1InputAddr = soAddr.add(0x75A5C+1);
//send('hook soAddr: ' + sha1InputAddr);

//var nativePointer = new NativePointer(sha1InputAddr‬);
//send("net native pointers:"+nativePointer);

//var result_pointer;
//intercept(sha1InputAddr);


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
};

//********************************hook native Two *********************************//

hooFgets();
hookOpen();
hookFopen();  
hookFread();
hookRead1();  

//hookStrlen();
//hookRead();  //打开有问题 

//********************************hook native Two end *********************************//


//size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;



function hookFread(){
    var target = Module.findExportByName("libc.so", 'fread');
	var read = new NativeFunction(target, 'int', ['pointer', 'int','int', 'pointer']);
    
	Interceptor.replace(read, new NativeCallback(function (buffer, size, count, stream) {
    var fd = fread(buffer, size, count, stream);
    var path = Memory.readUtf8String(buffer);
    console.log("hookFread Got read: " + path);
    return fd;
}, 'int', ['pointer', 'int','int', 'pointer']));
}



//ssize_t read [1]  (int fd, void *buf, size_t count);
function hookRead(){
    var target = Module.findExportByName("libc.so", 'read');
	var read1 = new NativeFunction(target, 'int', ['int', 'pointer', 'int']);
    
	Interceptor.replace(read1, new NativeCallback(function (fd, buf, count) {
    var fd = read(fd, buf, count);
   // var data = Memory.readUtf8String(buf);
    console.log(fd+"  -------- hookFread Got data: ");
    return fd;
   }, 'int', ['int', 'pointer', 'int']));
}




function hookOpen(){
	var openPtr = Module.findExportByName("libc.so", "open");
	var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
	Interceptor.replace(openPtr, new NativeCallback(function (pathPtr, flags) {
    var fd = open(pathPtr, flags);
    var path = Memory.readUtf8String(pathPtr);
    
    
   if (path.indexOf("data") > -1|| path.indexOf("proc") > -1 ) {
      // console.log("hookOpen Got fd: " + path);
    }
    console.log("hookOpen Got fd: " + path);
    return fd;
}, 'int', ['pointer', 'int']));
}


function hookFopen(){
		var target = Module.findExportByName("libc.so", 'fopen');
	    Interceptor.attach(target,{
		onEnter: function(args) {
	        var path = Memory.readCString(args[0]);
            if (path.indexOf("proc") > -1){
               console.log("hookFopen  file path:"+path);
	        }
            console.log("hookFopen  file path:"+path);
	    },
	    onLeave:function(retval){
	  		
	  	}
	});
}

var result_pointer;
function hookRead1(){
		var target = Module.findExportByName("libc.so", 'read');
	    Interceptor.attach(target,{
		onEnter: function(args) {
           // console.log(args[2]+"  hookRead1  file path:"+args[0]);
           // result_pointer=args[1];
	    },
	    onLeave:function(retval){
	  		 console.log("   **************  hookRead1  file path:"+retval);
          //  var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
          //  var offaddr = trace[0]; 
          //  var offaddr1 = offaddr - soAddr;
          //  console.log("地址|" + offaddr1.toString(16));
          //  console.log("trace:"+trace);
	  	}
	});
}



//int strlen(char *s);
function hookStrlen(){
		var target = Module.findExportByName("libc.so", 'strlen');
	    Interceptor.attach(target,{
		onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            console.log("  strlen  file path:"+path);
	    },
        
	    onLeave:function(retval){
	  		console.log("   **************  strlen  file path:"+retval);
	  	}
	});
}




function hooFgets(){
var fgetsPtr = Module.findExportByName("libc.so", "fgets");
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
    var retval = fgets(buffer, size, fp);
    var bufstr = Memory.readUtf8String(buffer);
    
    console.log(" hooFgets  file path:"+bufstr);
    
    if (bufstr.indexOf("TracerPid:") > -1) {
        Memory.writeUtf8String(buffer, "TracerPid:\t0");
        console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
    }
    return retval;
}, 'pointer', ['pointer', 'int', 'pointer']));  
};
   


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