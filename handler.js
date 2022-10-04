#!/usr/bin/node

const fs = require("fs");
const forge = require("node-forge");
const ChamberSigner = require("./ChamberSigner");
const nativeMessage = require('chrome-native-messaging');

var input = new nativeMessage.Input();
var transform = new nativeMessage.Transform(handleMessage);
var output = new nativeMessage.Output();

process.stdin
    .pipe(input)
    .pipe(transform)
    .pipe(output)
    .pipe(process.stdout)
;
var running = true;
write("HELLO");

  function write(data) {
     try {
       fs.appendFileSync('/tmp/pkcs7sign.log', data + "\n");
     } catch (e) {
       // no output as we can't really see logs
     }
  }

  function sendMessage (msg) {
    output.write(msg);
  }

  process.on('uncaughtException', (err) => {
    write("UNCAUGTHEXCEPTION");
    write(err.toString());
    sendMessage({message: "fail", error: err.toString()})
  })

  async function signData(type, data, passphrase) {
   try { 
      if (ChamberSigner.loadModule(passphrase)==false) {
        write("ERROR fail to open slot 0 on hardware key");
        return JSON.stringify({message: "fail", "error" : "fail to open slot 0 on hardware key"});
      }
   } catch(e) {
      write("ERROR " + e.toString());
      return JSON.stringify({message: "fail", "error" : "fail to open slot 0 on hardware key: " + e.toString()});
   }
   try {
    write("IN Async sign");
    var digest = forge.util.createBuffer(forge.util.decode64(data));
    var signature = ChamberSigner.signPkcs11(digest)
    var certificate = ChamberSigner.getCertificate()
    var scertificate = forge.util.encode64(JSON.stringify(certificate));
    var ssignature = forge.util.encode64(signature);
    var result = JSON.stringify({"message": type, "signature" : ssignature, "certificate" : scertificate });
    write("RESULT " + result);
    return result;
   } catch(e) {
    write("ERROR " + e.toString());
    return JSON.stringify({message: "fail", "error" : "exception: " + e.toString()});
   } finally {
    ChamberSigner.closeModule();
   }
  } 

  async function handleMessage(message, push, done) {
     try {
            // Do something with the data…
            write("Received message " + message.message + " " + message.data);
            if (message.message=="certificate") {
                write("Certificate message");
                var result = await signData("certificate", "", message.passphrase);
                sendMessage(result);
                write("Sending certificate back done");
            } else {
                write("Signature message");
                var result = await signData("signature", message.data, message.passphrase);
                sendMessage(result);
                write("Sending signature back done");
            }
       } catch (e) {
            write("ERROR IN PROCESSDATA");
            write(e.toString()); 
       } finally {
            done();
       }
  }
