## RSA2Util的前端调用方法
### 公钥加密、私钥解密
    私钥前端加密，公钥后端解密
`npm i wxmp-rsa -S`
```js
import WxmpRsa from 'wxmp-rsa'

// 下面的密钥是错误的哦！
const publicKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqsRXUV4426vmPaxKUTP0SN/YqJB'

const privateKey = 'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKqxFdRXjjbq+Y9rEpRM/RI39ionkn9lmm7jstjfvd2QM97Oc+9sc9zVVNIbjk8tOZvdb/eNXs2u35ZYnb1YQVJJI7D4nElAZVN7FPAsw6OcRTuwnJfwfBzQprsr74Rc9ujjhcR1G6Qk9PyB5fedK1acUk2iehVuiZE7RmTMfTt7AgMBAAECgYEAoTzERSAr676M3Sgklcgf6pzIQMu+u+7rMcKPSAQaIvg7t0VICKtmyv0NsadsB2jOGWjUgoCdRCfjdu7gmmKK='

// TODO 怎么使用还有待考究
const rsa = new WxmpRsa()

// 加密
export function encrypt(txt) {
  rsa.setPublicKey(publicKey) // 设置公钥
  return rsa.encryptLong(txt) // 对数据进行加密
}

// 解密
export function decrypt(txt) {

  rsa.setPrivateKey(privateKey) // 设置私钥
  return rsa.decryptLong(txt) // 对数据进行解密
}

```