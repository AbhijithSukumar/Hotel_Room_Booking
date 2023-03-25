import AES from "aes-encryption";
import crypto from "crypto"

const secretKey='MySecretKey'
const hash = crypto.createHash('sha256').update(secretKey).digest('hex');

const aes=new AES()
aes.setSecretKey(hash)


export function encrypt_token(data) {
  const encryptedData=aes.encrypt(data)
  return encryptedData;
}

export function decrypt_token(data) {
  const decripted=aes.decrypt(data)
  return decripted;
}