hash-toolkit
============

Toolkit to calculate bitwise-hash and exploit the hash length extension attack

Currently supporting algorithms: MD5

help
====

```
usage: md5.py [-h] [--length LENGTH] [--prev PREV] [--blocks BLOCKS] message

Toolkit to calclate bitwise-hash and exploit the hash length extension attack

positional arguments:
  message               message to calculate hash

optional arguments:
  -h, --help            show this help message and exit
  --length LENGTH, -l LENGTH
                        bitwise message length
  --prev PREV, -p PREV  result of previous block process
  --blocks BLOCKS, -b BLOCKS
                        number of already processed blocks
  --verbose, -v         show detailed information
```

samples
=======

- calculate hash
```
% ./md5.py ''
d41d8cd98f00b204e9800998ecf8427e
% ./md5.py foo
acbd18db4cc2f85cedef654fccc4a4d8
```

- calculate bitwise-hash
```
% ./md5.py --length 24 foo
acbd18db4cc2f85cedef654fccc4a4d8
% ./md5.py --length 21 foo
2968540c7ae8396d4e38519e0eb611e0
```

- exploit the hash length extension attack

We only know that key's length is 6 bytes and md5(key + 'Originalmessge') is 1cb7e16270bf9eb088320f2b366aadbf.
key's content is unkown.
```
% echo -en 'passwdOriginalmessage' | md5sum
1cb7e16270bf9eb088320f2b366aadbf
% ./md5.py --prev 1cb7e16270bf9eb088320f2b366aadbf --blocks 1 Exploitmessage
e641ac2e734e14f4c78952d12d6be69d
% echo -en 'passwdOriginalmessage\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\x00\x00\x00\x00\x00\x00\x00Exploitmessage' | md5sum
e641ac2e734e14f4c78952d12d6be69d
```
So we'll send 'Originalmessage\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\x00\x00\x00\x00\x00\x00\x00Exploitmessage' and e641ac2e734e14f4c78952d12d6be69d.
