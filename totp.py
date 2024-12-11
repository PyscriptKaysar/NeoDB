import pyotp
import qrcode



#one time thing method for one users register account, give them qr for them to scan in google auth app

def generate_key():
    user_key = pyotp.random_base32()
    return user_key



def verify_otp(google_otp, user_key):
    otp = get_otp(user_key)
    otp.verify(google_otp)

def get_otp(user_key):
    otp = pyotp.TOTP(user_key)
    return otp



temp_user_key = generate_key()
def generate_URI() -> URI:
    otp = get_otp(temp_user_key)
    URI = otp.provisioning_uri(otp)
    print(otp)
    print(URI)
    return URI

def create_qr(URI):
    img = qrcode.make(generate_URI())
    return img
