#AES-GCM暗号化に関する詳細説明は以後追記予定です。

"""
「ソルト(salt)」
パスワードのハッシュ化には、ソルト(salt) と呼ばれるランダムデータをパスワードと連結してハッシュ化し、
ソルトとハッシュ値をDB保存します。
例えば、例えば100万件パスワードハッシュ情報が流出してしまった場合、ソルト無しの場合、
よく利用されるパスワードをハッシュ化してDB検索することで簡単にユーザIDとパスワードのペアを見つけることができますが、
ソルト有りの場合、ソルトとハッシュ値が流出しても1件1件毎にソルト付きでハッシュ計算しなくてはならず、
解析のための計算量が増え、安全性が高まります。

引用:https://www.tohoho-web.com/ex/crypt.html
"""


import os
import hashlib
from Crypto.Cipher import AES


#暗号化
def encrypt(message, password):


    #暗号化の鍵を生成するために必要な乱数を生成するための16バイトのバイト列を生成。
    salt = os.urandom(16)


    """
    暗号化の鍵をハッシュ関数(scrypt関数)によってパスワードとsaltから生成。
    上記関数の引数「n=2**14」は暗号の計算負荷に該当する部分であり、最低でも2**14以上を推奨。
    あまりにも計算負荷を大きくすると動作確認に苦労するため、今回は n=2**14 を採用。
    引数「dklen=32」はAES-GCM暗号の鍵長が256bitまでなので必須である。
    """
    key = hashlib.scrypt(password=password, salt=salt, n=2**14, r=8, p=1, dklen=32)


    """
    AES-GCM暗号化用インスタンスを生成。
    初期化ベクトルに相当するノンス(nonce)はPyCryptodomeのGCMモードでは自動で生成されるので、
    再利用してしまうことはない
    """
    cipher = AES.new(key, AES.MODE_GCM)





    #暗号化(暗号化した文字列とタグを生成する)。
    cipher_text, tag = cipher.encrypt_and_digest(message)


    #パスワード以外の複合化に必要なデータをリストで返す。
    return [salt, cipher_text, cipher.nonce, tag]

#複合化
#やっていることは暗号化の逆。のちに詳細のコメントアウトを追加予定。
def decrypt(encrypted_message, password):
    salt, cipher_text, nonce, tag = encrypted_message
    key = hashlib.scrypt(password=password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(cipher_text, tag)


#入力欄
message = 'This is a message.'
password = 'password'


encrypted_message = encrypt(message.encode(), password.encode(),)

crypt_list = ['salt', 'cipher_text', 'nonce', 'tag']
for i in range(len(crypt_list)):
    print(f'{crypt_list[i]}:',encrypted_message[i])


#出力
decrypted_message = decrypt(encrypted_message, password.encode()).decode()

print("decrypted_message: ", decrypted_message)