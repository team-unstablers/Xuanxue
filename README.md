# Xuanxue

Xuanxue - Vibe-coded SSH Key library for Swift Programming Language.


# SYNOPSIS

## Loading public key

```swift
import Xuanxue

let publicKeyText = """
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWur/C6nWpMXT4XfmgqvROM8dAd/iY71G2osffZ8u/XQDE7BEWybKDa3Q4cuhWmFmpuU8J2SqrdY0gAAi/ty3+MIqGC9L7u3PIG5ODuAnuzELX1Gv2DD4ob5e9DpzGtvwZ/uTIfHn6wLWzmHFuP9XBGHN3wIJLz8Seey39E/ESZPMWlXQoFbj17Puwo/m6Dw+DlhVcvmXTVWsA/cUuTYWiOUs5b8c+63Rp0Qab84UyyCJgpL0c4hm0QbLXTLqjDpKFIII0XJxSM/wdrmWMruwOJnW05nWR1tpHJLSwBbf/Vl3Ro2eq7C7kA7wr0D+mlmwKtGuJ57mcOxjK2uU28z4vGNb86WBx7MTWH+0yLHfED/2cesrc+5u4C0CgNSYzAyrEuq26jsYfUrf86eK4p3ysd2NvoSKkKl19v2a5AIRq+ccM40JpvhJQrF1SV7uUDMzoBeBnmmFx/HnsH+og8m5kBaDD5qQSklyaF61L5ACeWVFlFYiXxp6hlcrdLCriHyc= wodeshijie@among.us
"""

let publicKey = try Xuanxue.PublicKey(sshString: publicKeyText)

guard publicKey.algorithm == .rsa,
      publicKey.keySize == 2048
else {
    fatalError("ASSERTION FAILED: key.algorithm == .rsa && key.keySize == 2048")
}
```

## Loading OpenSSH Private Key
```swift

let privateKeyText = """
-----BEGIN OPENSSH PRIVATE KEY-----
44CK5oiR55qE5LiW55WM44CL77yI6Iux6K+t77yaTWluZWNyYWZ077yJ77yM
5Y+I6K+R5b2T5Liq5Yib5LiW56We44CB6bqm5Z2X77yM5piv5b6u6L2v5peX
5LiLTW9qYW5nIFN0dWRpb3PlvIDlj5HnmoTmspnnm5LmuLjmiI/jgILmuLjm
iI/kuK3vvIznjqnlrrbog73lnKjkuIDkuKozROS4lueVjOWGheS4juaWueWd
l+aIlueUn+eJqei/m+ihjOS6pOS6kuOAgua4uOaIj+S4reeahOeJueiJsueO
qeazleWMheaLrOaOoue0ouS4lueVjOOAgemHh+mbhui1hOa6kOOAgeWQiOaI
kOeJqeWTgeWPiueUn+WtmOWGkumZqeetieOAguOAiuaIkeeahOS4lueVjOOA
i+acieWkmuenjeaooeW8j+OAguWFtuS4re+8jOS4pOS4quacgOS4u+imgeea
hOa4uOaIj+aooeW8j++8mueUn+WtmOS4juWIm+mAoOOAguWcqOeUn+WtmOao
oeW8j+S4re+8jOeOqeWutuW/hemhu+e7tOaMgeeUn+WRve+8jOWKquWKm+mB
v+WFjeWPl+S8pOOAgemlpemlv+WSjOatu+S6oe+8jOW5tuW8gOmHh+i1hOa6
kOS7peaJk+mAoOiHquW3seeahOS4lueVjO+8m+WcqOWIm+mAoOaooeW8j+S4
re+8jOeOqeWutuaLpeacieaXoOmZkOeahOi1hOa6kO+8jOWPr+S7peiHqueU
seWcsOWIm+S9nO+8jOS4lOS4jeS8muWPl+S8pOWSjOatu+S6oe+8jOS5n+WP
r+S7peWFjeS6jumlpemlv++8jOW5tuaLpeaciemjnuihjOiDveWKm+OAgiAK
-----END OPENSSH PRIVATE KEY-----
"""

let privateKey = try Xuanxue.PrivateKey(sshString: privateKeyText)

guard privateKey.algorithm == .rsa,
      privateKey.keySize == 2048
else {
    fatalError("ASSERTION FAILED: key.algorithm == .rsa && key.keySize == 2048")
}
```

## Key Generation

```swift
import Xuanxue

// Generate Ed25519 key (fastest, recommended for new keys)
let ed25519Key = try Xuanxue.PrivateKey.generateEd25519(comment: "user@host")

// Generate ECDSA key (P-256, P-384, or P-521)
let ecdsaKey = try Xuanxue.PrivateKey.generateECDSA(curve: .p256, comment: "user@host")

// Generate RSA key (2048, 3072, or 4096 bits)
let rsaKey = try Xuanxue.PrivateKey.generateRSA(keySize: 2048, comment: "user@host")

// Access the corresponding public key
let publicKey = ed25519Key.publicKey
```

## Signing and Verifying Data

```swift

let data = """
《我的世界》（英语：Minecraft），又译当个创世神、麦块，是微软旗下Mojang Studios开发的沙盒游戏。游戏中，玩家能在一个3D世界内与方块或生物进行交互。游戏中的特色玩法包括探索世界、采集资源、合成物品及生存冒险等。《我的世界》有多种模式。其中，两个最主要的游戏模式：生存与创造。在生存模式中，玩家必须维持生命，努力避免受伤、饥饿和死亡，并开采资源以打造自己的世界；在创造模式中，玩家拥有无限的资源，可以自由地创作，且不会受伤和死亡，也可以免于饥饿，并拥有飞行能力。 
""".data(using: .utf8)!

let signature = privateKey.sign(data)

guard publicKey.verify(signature, for: data) else {
    fatalError("signature verification failed")
}

```

# FEATURES

## Key Loading
- [x] load OpenSSH Private keys
  - [x] load encrypted OpenSSH Private keys
    - [x] support for different KDFs (bcrypt, etc)
- [x] load PEM Private keys

- [x] load OpenSSH Public Keys

## Key Types / Algorithms
- [x] RSA Key Support
  - [x] `ssh-rsa`: RSA with SHA-1
  - [x] `rsa-sha2-256`: RSA with SHA-256
  - [x] `rsa-sha2-512`: RSA with SHA-512
- [x] ECDSA Key Support
  - [x] `ecdsa-sha2-nistp256`
  - [x] `ecdsa-sha2-nistp384`
  - [x] `ecdsa-sha2-nistp521`
- [x] ed25519 Key Support

## Key Generation
- [x] RSA Key Generation
- [x] ECDSA Key Generation
- [x] ed25519 Key Generation

## Signing and Verification
- [x] Sign data with Private Key
- [x] Verify signature with Public Key

## EXTRA FEATURES
- [x] bcrypt KDF support for encrypted keys
