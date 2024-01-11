import time
import urllib3
import requests
import json
import math
import base64
from Crypto.Cipher import AES
import Crypto.Random
import binascii
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

kurl_1=sys.argv[1]
kurl_2=sys.argv[2]

class Cipher_AES:
    cipher = getattr(Crypto.Cipher, "AES")
    pad = {"default": lambda x, y: x + (y - len(x) % y) * " ".encode("utf-8"),
           "PKCS5Padding": lambda x, y: x + (y - len(x) % y) * chr(y - len(x) % y).encode("utf-8")}
    unpad = {"default": lambda x: x.rstrip(),
             "PKCS5Padding": lambda x: x[:-ord(x[-1])]}
    encode = {"base64": base64.encodebytes,
              "hex": binascii.b2a_hex}
    decode = {"base64": base64.decodebytes,
              "hex": binascii.a2b_hex}

    def __init__(self, key=None, iv=None, cipher_method=None, pad_method="default", code_method=None):
        self.__key = key if key else "abcdefgh12345678"  
        self.__iv = iv if iv else Crypto.Random.new().read(Cipher_AES.cipher.block_size)  
        self.__cipher_method = cipher_method.upper() if cipher_method and isinstance(cipher_method,
                                                                                     str) else "MODE_ECB"  
        self.__pad_method = pad_method  
        self.__code_method = code_method  
        if self.__cipher_method == "MODE_CBC":
            self.__cipher = Cipher_AES.cipher.new(self.__key.encode("utf-8"), Cipher_AES.cipher.MODE_CBC,
                                                  self.__iv.encode("utf-8"))
        else:
            self.__cipher = Cipher_AES.cipher.new(self.__key.encode("utf-8"), Cipher_AES.cipher.MODE_ECB)

    def __getitem__(self, item):
        def get3value(item):
            return item.start, item.stop, item.step

        type_, method, _ = get3value(item)
        dict_ = getattr(Cipher_AES, type_)
        return dict_[method] if method in dict_ else dict_["default"]

    def encrypt(self, text):
        cipher_text = b"".join([self.__cipher.encrypt(i) for i in self.text_verify(text.encode("utf-8"))])
        encode_func = Cipher_AES.encode.get(self.__code_method)
        if encode_func:
            cipher_text = encode_func(cipher_text)
        return cipher_text.decode("utf-8").rstrip()

    def decrypt(self, cipher_text):
        cipher_text = cipher_text.encode("utf-8")
        decode_func = Cipher_AES.decode.get(self.__code_method)
        if decode_func:
            cipher_text = decode_func(cipher_text)
        return self.pad_or_unpad("unpad", self.__cipher.decrypt(cipher_text).decode("utf-8"))

    def text_verify(self, text):
        while len(text) > len(self.__key):
            text_slice = text[:len(self.__key)]
            text = text[len(self.__key):]
            yield text_slice
        else:
            if len(text) == len(self.__key):
                yield text
            else:
                yield self.pad_or_unpad("pad", text)

    def pad_or_unpad(self, type_, contents):
        lambda_func = self[type_: self.__pad_method]
        return lambda_func(contents, len(self.__key)) if type_ == "pad" else lambda_func(contents)
    
url_1="1porCsgzs74SROgrLk7XmNpkrhe/S6NGsYkCx4iVUJzu61Ctio4FqyQiotx2tDyf/jvr9QUF5dct+HKqbxW0tFIs7w0o0RZjJcIOGBCojUoUeTO5B+ViIpy/qquSYzycv6tprCcV5RXKWa5BepewDtlGpn6nhSmLwRzeJ2GpsUqMZhpT5ZgCTayLwN1VXQb7Mf3M9tS86PNv5m3OOuUKBg=="
url_2="20tEx3DP7446sXhYB3JwJnRfC8e4gihzgaZyZacTimol6YysXpkTh205So43sTQ0s5IrcptkQWNrjCcR2a/Q2FUJtbHHM+obGXVltlmDoPgD3+Byz0CgNeRBl1xhGpTRh06JN5/vTf4NKlgz7HimFi3q3D7FYECSeMX0xhrFd7+eNWdmo4zqq6PwTrzvJwLNBwOTV/Uo1EWcBP2MgVtkdhxMAu7uPaWE/HYjWkuZlj/dhaf1wyQiPehaqCjaD7IAyEpNaca3DmtPXAt8QhMboA=="
url_3="1porCsgzs74SROgrLk7XmHWkC2wT5qHs9SI2m2eL0DnQgUvUwaHYyPSmBArmvf3uy5tLD8ehMRwSZmdR3TEyMEi3wECooFq80wkzvsSxcGzazdJtiXeIEGj8saXoX3cGL4EXcHspaeJvy+AqlBO/3JPrigNyMMsZdWv4DyZoykznqOECIKO7qSG67p/zurTo"
url_4="20tEx3DP7446sXhYB3JwJnRfC8e4gihzgaZyZacTimol6YysXpkTh205So43sTQ0s5IrcptkQWNrjCcR2a/Q2FUJtbHHM+obGXVltlmDoPgD3+Byz0CgNeRBl1xhGpTRh06JN5/vTf4NKlgz7HimFi3q3D7FYECSeMX0xhrFd7+eNWdmo4zqq6PwTrzvJwLNBwOTV/Uo1EWcBP2MgVtkdhxMAu7uPaWE/HYjWkuZlj/dhaf1wyQiPehaqCjaD7IAl5KurlpnrhTEB5P/gw7x+V8s+kSws5Zrw88pYkNctXo="

cipher_method = "MODE_CBC"
pad_method = "PKCS7"
code_method = "base64"
key, iv = "ks9KUrbWJj46AftX", "ks9KUrbWJj46AftX"


def Cipher_AESS(body):
    Cipher_AESb=Cipher_AES(kurl_1, kurl_2, cipher_method, pad_method, code_method).decrypt(body)
    return Cipher_AESb


url1 = Cipher_AESS(url_1) + str(math.floor(time.time()*1000)) + Cipher_AESS(url_2)
url2 = Cipher_AESS(url_3)+ str(math.floor(time.time() * 1000)) + Cipher_AESS(url_4)
dates = requests.get(url1,verify=False).json().get("res")
print(url1)
print(url2)
nodes_data = []
for i in dates:
    for k in i['data']:
        nodes_data.append(k)
        
with open("Proxy/节点.txt", "w", encoding="UTF-8") as f:
    f.write("")
for i in nodes_data:
    node_id = str(i['id'])
    node_name = i['name']
    node_AES = requests.get(url2 + node_id,verify=False).text
    if len(node_AES) < 100:
        continue
    # 解密
    Temp = Cipher_AES(key, iv, cipher_method, pad_method, code_method).decrypt(node_AES).replace("vmess://", "")
    node_unAES = json.loads(base64.decodebytes(Temp.encode()).decode())
    #重命名
    node_unAES["ps"] = node_name
    Temp = "vmess://" + base64.encodebytes(json.dumps(node_unAES).encode()).decode()
    with open("Proxy/节点.txt", "a", encoding="UTF-8") as f:
        f.writelines(Temp.replace(' ', '').replace('\n', '') + "\n")

