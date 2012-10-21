import hashlib
import hmac
import random
import string
import cgi
import logging

from conf import SECRET_KEY

def make_salt(length=7):
    '''Create salt'''
    return "".join([random.choice(string.letters + string.digits) for i in range(length)])

def make_hash(text, salt=make_salt()):
    h = hmac.new(str(salt), str(text), digestmod=hashlib.sha256).hexdigest() #hmac does not seem to handle unicode objects, hence the str casting
    return "%s,%s" % (h, salt)

def valid_password(text, h):
    salt = h.split(",")[1]
    return make_hash(text, salt) == h

def valid_cookie_hash(session_str):
    session_hash, user_id = session_str.split("|")
    return make_hash(user_id, SECRET_KEY).split(",")[0] == session_hash

def make_cookie_hash(user_id):
    res = make_hash(user_id, SECRET_KEY)
    cookie_hash = res.split(",")[0]
    return "%s|%s" % (cookie_hash, user_id)

def clean_input(input_string, evil_chars=[]):
    input_string = cgi.escape(input_string)
    for char in evil_chars:
        input_string = input_string.replace(char, "")
    return input_string
