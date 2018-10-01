import binascii
import ed25519
import hashlib
import msgpack

publicKey = "b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068"
messageHex = "9512b06eac4d0b16e645088c4622e7451ea5a1ccef01da0040578a5b22ceb3e1d0d0f8947c098010133b44d3b1d2ab398758ffed11507b607ed37dbbe006f645f0ed0fdbeb1b48bb50fd71d832340ce024d5a0e21c0ebc8e0e"
message = binascii.unhexlify(messageHex)

vk = ed25519.VerifyingKey(publicKey, encoding='hex')

unpacked = msgpack.unpackb(message)
signature = unpacked[4]
print("signature: {}".format(binascii.hexlify(signature)))
try:
    tohash = message[0:-67]
    print("message: {}".format(binascii.hexlify(tohash)))
    hash = hashlib.sha512(tohash).digest()
    print("signedData: {}".format(binascii.hexlify(hash)))
    vk.verify(signature, hash)
    print("message signature verified")
except Exception as e:
    print("message signature verification failed: {}".format(str(e)))
