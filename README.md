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
- [ ] load OpenSSH Private keys
  - [ ] load encrypted OpenSSH Private keys
    - [ ] support for different KDFs (bcrypt, etc)
- [ ] load PEM Private keys

- [ ] load OpenSSH Public Keys

## Key Types / Algorithms
- [ ] RSA Key Support
  - [ ] `ssh-rsa`: RSA with SHA-1
  - [ ] `rsa-sha2-256`: RSA with SHA-256
  - [ ] `rsa-sha2-512`: RSA with SHA-512
- [ ] ECDSA Key Support
  - [ ] `ecdsa-sha2-nistp256`
  - [ ] `ecdsa-sha2-nistp384`
  - [ ] `ecdsa-sha2-nistp521`
- [ ] ed25519 Key Support

## Key Generation
- [ ] RSA Key Generation
- [ ] ECDSA Key Generation
- [ ] ed25519 Key Generation

## Signing and Verification
- [ ] Sign data with Private Key
- [ ] Verify signature with Public Key

## EXTRA FEATURES
- [ ] bcrypt KDF support for encrypted keys
