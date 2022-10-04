
const graphene = require('graphene-pk11');
const forge = require('node-forge');

class ChamberSigner extends Object {

 static loadModule = (passphrase) => {
    let Module = graphene.Module;
    this.module = Module.load("/usr/lib/WebSmartPack/libidop11.so", "Chambersign");
    this.module.initialize();
    var slot = this.module.getSlots(0);
    this.session = slot.open();
    this.session.login(passphrase);
    return true;
 }

 static closeModule = () => {
    this.session.logout();
    this.module.finalize();
 }

 static getCertificate = () => {
    let certsObj = this.session.find({class: graphene.ObjectClass.CERTIFICATE});
    let certs = certsObj.innerItems;
    let cert = this.session.getObject(certs[0]);
    let decoded = forge.asn1.fromDer(cert.value.toString('binary'));
    return forge.pki.certificateFromAsn1(decoded);
 }

 static signPkcs11 = (digest) => {
        // https://stackoverflow.com/a/47106124
        const prefix = Buffer.from([
                0x30, 0x31, 0x30, 0x0d,
                0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03,
                0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20
        ]);
        let buf = Buffer.concat([prefix, Buffer.from(digest.toHex(), 'hex')]);
        let keys = this.session.find({ class: graphene.ObjectClass.PRIVATE_KEY });
        let pkeyBuffer = keys.innerItems[0]
        let pkeyObject = this.session.getObject(pkeyBuffer);
        let sign = this.session.createSign("RSA_PKCS", pkeyObject);
        let result = sign.once(buf).toString('binary');
        return result;
 }

} 

module.exports = ChamberSigner;

