import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from base64 import b64decode,b64encode


keyprivPEM="MIICXgIBAAKBgQDR6J4r+KpEhhAd3bwWSI1oPHrxYvSrZI7CVg3g/bUZtL8Fz0MGmpd8fWzes+akgBsvUsuTjk4Te3PV/b5qleILpePjKYCQVA0cgXKt8r6mW7AMx8pgQ88OIiG+d3vm7IyBkFdTfgQPdXjYKvvvBOqJUehIJAejV9akUm1yb59VjwIDAQABAoGBAL1o+zlQVEwq8OYSTIOLClaRpJqmoYL65TsFLdbk+ILuryRN5vxRiPpjr1ax3SB5HI6yVlKaqWc5Ech6BFXnU6VtCIWV1L2KAvCM3fDVW8xCwn8nGbfbUR1hR+crgy54xzTvp6zwJ3o3zECDGgxzqa4poEBpsYovOQxYo4E0pkk5AkEA/a6kx2r8eZCTySevv4Q6mHGX25bS/zd0svtmWfTc8ORHL2M2PpPs782si/ruJr6xQ0hooVMSZRNnWuU5+JFbLQJBANPTlsdEbqtEy/C8WgYrgmnesmL2OnbILPQq/vAEE27qlCyhp3nDpaCAa71dV2eJTVFhEIBWbgcf+6henaqIOSsCQGL3IeOGMk6+f1kHOYHudOmJzyNkeJYGLWmxt+E6LINxmu+6tau+C74Vr83AK+5DkGXeNqtQ/CkgY77LFE2Lb1UCQQCXCgY269qlkJaCfysJvzhsWPiFi+DAFZfIOmgxqBZbPjSNZm7OaezNdwRbsBTEpKhW4IktmXM27V05/s0ZbaylAkEA/ZYGRWbdGoZtBWNS5i3vHQr0SdoWGwvklQONc0klW0vlKbghNq8e+p6LbMygAi3EzJcpPt0n4C3M2NVIV6LRvw=="
keyprivDER = b64decode(keyprivPEM)
keyPriv=RSA.importKey(keyprivDER)
keyPub="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR6J4r+KpEhhAd3bwWSI1oPHrxYvSrZI7CVg3g/bUZtL8Fz0MGmpd8fWzes+akgBsvUsuTjk4Te3PV/b5qleILpePjKYCQVA0cgXKt8r6mW7AMx8pgQ88OIiG+d3vm7IyBkFdTfgQPdXjYKvvvBOqJUehIJAejV9akUm1yb59VjwIDAQAB"
while(True):
    input_op=input("Input operations to sign: ")
    msg = input_op.encode()
    h = SHA256.new(msg)
    signature = pss.new(keyPriv,salt_bytes=0).sign(h)
    signature_clean=hex(int.from_bytes(signature,byteorder='big')).strip("0x")
    print("Signature: "+signature_clean)
    echoStr="'"+keyPub+str("\\t")+signature_clean+str("\\t")+input_op+str("\\0")+"'"
    cmd="echo "+echoStr+">/tools/opentitan/gpio0-write"
    os.system(cmd)
    print("[+] Message sent to device")