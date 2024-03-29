
import pgpy
import hexdump

KEY_PUB = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mI0EV1y9XAEEAMn1ZI3rFLbGwGbO9WOSnfqlsDgokyRN3ifSJ4yrtteLKiqyXUl2
fGIJzsW6FhAisnpr46pE2m0C7mpc7PAluB/aPzE95RLcQuNLvMzAx4Jj5rs3f3Zn
C4DuPkEVNM1NYow+ef9swH1UdsZxrqALHS8ojGaTECUEJ2R2+CUfWLpTABEBAAG0
C3dpbGxpIDx3QGI+iLgEEwECACIFAldcvVwCGwMGCwkIBwMCBhUIAgkKCwQWAgMB
Ah4BAheAAAoJEEnsK2RHSBGcOjoD/RD0bOdls0RXOvgCg5VVFFVTMS6rRBq3M8wL
HCwQKnA0qtNnE1cSIhS7Xp11fJw9+0bLfq/aknkwZWGT04Hov+sar3Yqk9jVJMm/
rBkwER90rZz/pdaSX8vlBjzWeVidptiE4PyPKIpAszhgG1nIdOH13DFgdTB01v/8
qI+YHWvZuI0EV1y9XAEEAOx02seUsv3iGqUBfUGWOSKNSk6IEJnL4APIBkzusWnY
PLrtLbI/ZK9BY20TbxZbdctIOw7b+l3Px4y0Y+4NFCt8tE7iHyyUzmw1btzNIbgp
TLssu85xYQL4CX1yBnAsK5lRjJNryp3W6a/hz1v/bUQzwPTEESZMm7/MkARRLuMN
ABEBAAGInwQYAQIACQUCV1y9XAIbDAAKCRBJ7CtkR0gRnKlXA/0ZVaZHEUPuTNL6
G550HC5atTO4UoZFi0UtzLVVXDlacGiEhNZb81cXWP5M3K/GN3aeqjZpAFej30ko
F+N5JUwtcl7VfrIfRw+pZPNcOBoMdlKzpYrMYlKELTNrQzMt0Fqfvfs9C6ReDgep
VY1s5iZMWApgf6zBkQXPb8n0FYxinQ==
=WTDR
-----END PGP PUBLIC KEY BLOCK-----
'''.lstrip()

KEY_PRIV = '''-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQHYBFdcvVwBBADJ9WSN6xS2xsBmzvVjkp36pbA4KJMkTd4n0ieMq7bXiyoqsl1J
dnxiCc7FuhYQIrJ6a+OqRNptAu5qXOzwJbgf2j8xPeUS3ELjS7zMwMeCY+a7N392
ZwuA7j5BFTTNTWKMPnn/bMB9VHbGca6gCx0vKIxmkxAlBCdkdvglH1i6UwARAQAB
AAP/Sc5G0cCUINnQraG7twh5eIS9ukBFydI1OmtIbdXBK9NddR4bDoJhIXkBGmyP
rJTpkejE2lBwXL9h/vf31SmLuF28NtKtzGlSlELYAcXKEvxBm3vTZWDeN39vJDpL
HUCZ9PRQSkmZk6us16Olv0bibMA7p1UECqFZ+ifBt9rCs1UCANTI2mRi7daZk87/
ldNURFLKXmaX4YW9gAK61rwFvRNJQZM8fCiXOLct8vKrfO61rNSoGgG25N90n+Ph
ptJFrg8CAPL5q7w1lfPREPbnI8lGnpZ08rL/tuj+hLcssNoQjqwPQn05Bxt7PgGO
HiKx75GOSUqCFG8mxYSrzdmQs5m+c30CAKEOJr3nxXTOSUZDsqakMhZ0/JSfn8vb
3gMP1/Ffb55NiGehP52MgogoTH/0QdZ93ViYy5nLW6HWuaPDr9wGYFythrQLd2ls
bGkgPHdAYj6IuAQTAQIAIgUCV1y9XAIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgEC
F4AACgkQSewrZEdIEZw6OgP9EPRs52WzRFc6+AKDlVUUVVMxLqtEGrczzAscLBAq
cDSq02cTVxIiFLtenXV8nD37Rst+r9qSeTBlYZPTgei/6xqvdiqT2NUkyb+sGTAR
H3StnP+l1pJfy+UGPNZ5WJ2m2ITg/I8oikCzOGAbWch04fXcMWB1MHTW//yoj5gd
a9mdAdgEV1y9XAEEAOx02seUsv3iGqUBfUGWOSKNSk6IEJnL4APIBkzusWnYPLrt
LbI/ZK9BY20TbxZbdctIOw7b+l3Px4y0Y+4NFCt8tE7iHyyUzmw1btzNIbgpTLss
u85xYQL4CX1yBnAsK5lRjJNryp3W6a/hz1v/bUQzwPTEESZMm7/MkARRLuMNABEB
AAEAA/9lWZ7uvcdMt+3YvP8trhCWRT5M09hdu3us0z8UGZlUt1kse/3CsZZb4iiW
N6a9S/184NxjfZlePXGYVzef8N4sBIwzN5N6F11wa0xxGx2+e8nHpuMPnBYVIGre
yAZBVB41CglR8rof7SYUysi5puTuBv/yVSdzBM3cSuWPZ94GxwIA7RkjTSrLLdzz
lxHrdyI//8JcIfxB6RO3jXLB2wfI3ge15OOo44G5V2bdcSVxOdk3gDSj/TtqCgyF
u+0aJgYSjwIA/06erCfS+F/nn0oR2h3EFxxeVYyRkPU5rVgws9ocMeNo3X5/ehAH
MeM3C03opIl0vGy/jJatnfROplpJin7OowIAmCQhVN06ZEFJSUHjmXmmjsf8JEs3
nNrVYESGdlECRcUIu9Vv00rbZ3NjymbJjyxKhd7pIrfmIzKnSxZNKnYGy58FiJ8E
GAECAAkFAldcvVwCGwwACgkQSewrZEdIEZypVwP9GVWmRxFD7kzS+huedBwuWrUz
uFKGRYtFLcy1VVw5WnBohITWW/NXF1j+TNyvxjd2nqo2aQBXo99JKBfjeSVMLXJe
1X6yH0cPqWTzXDgaDHZSs6WKzGJShC0za0MzLdBan737PQukXg4HqVWNbOYmTFgK
YH+swZEFz2/J9BWMYp0=
=iHir
-----END PGP PRIVATE KEY BLOCK-----
'''.lstrip()

# via: http://r6.ca/privatekeys.html
KEY_PRIV2 = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.2.3 (OS/2)

lQHWBD3X7JABBADfDcT9WgUZsAXC2jaLXbVRbkI/vmZWqFT1bBTicnHEOf0EZRKl
o2eIJWf0UIMvBC840efecOGKEmtubHyyas5aSDThQZM8PyCKRrJhGX02UHwCvNRi
XzAD1wteFyGtkVYmlHTR84fjyk9V1BlsZLNTZdTbKQ//Yuxww1qPTrlqNwAGKQAD
/2ddy62aG1bUsX/CyBse8B9+BbmjKS5m+6ntZ1Y1CQOFBNySvbbn0lHS5T9Eh7gh
KJ10AU4bVclZtOg+wyb5TORKNJ6ywjvj+DDMFekoWlfMwhw+utZVEpbJkK7vJNQg
jGBX0+L2uEbv/Z5wFpucoLxNX5fg+nDUxzP+d3VXAlLJAgDrZOc2usLMfMXNh+p0
5xfSAa8QmpumEM/1ARyV12BLhf0/nuVIZPkK9mfTdO5xk/OC35FhJLqQzHSoyNeW
wPRvAgDylFK+/3F5O1ssj2SQ4KRmULhoOs/Lpj9XgTPOFcbkoT58XYmkNvNbKCxS
It1QS0LQNHtOOqIvZKbagnckopq5Af9IGvyE53vEmp6lfop0yZFmO8NQPbcv+B5k
rUAValTyeDTyH7Qc2pdm/SGok47vSc+5Uyyx6/X6hUHF1sfSIoVVrC60hFJ1c3Nl
bGwgU3RldmVuIFNoYXduIE8nQ29ubm9yIChMT1cgU0VDVVJJVFkgLSBzZWUgPGh0
dHA6Ly9tYXRoLmJlcmtlbGV5LmVkdS9+cm9jb25ub3IvcHVibGlja2V5cy5odG1s
PikgPHJvY29ubm9yQG1hdGguYmVya2VsZXkuZWR1Poi4BBMBAgAiBQI91+yQAhsD
BQkB4TOABAsHAwIDFQIDAxYCAQIeAQIXgAAKCRBNPmjuaEZDWZ9vBADQCY9J5ZnV
VYfQBf5F3d6yhNxzXJaFIHEemsBA37dgwCJc3+49KBBJFB91PFlVwgz9PCgux8YJ
yUDsDh56pzXycCxcBav0O/MBapN1rq5/X22vtKrKxSfKjMLfQlto7VWv9vNwzlZA
ClJPYBDOZt5DxA3RECsuNxEvb28bfT5epQ==
=VufU
-----END PGP PRIVATE KEY BLOCK-----
'''.strip()

FOR_NOVA = '''
-----BEGIN PGP MESSAGE-----

hQGMA5ZlRheam2vrAQwAg0LF3TNDMFM17C87SCewzD7aD5rSxS7hdZov6AjukTc+
IqWEV+l/Bbe0vrDQTPRAeoHx+mvFtpBmVq3LN9CgwQhxbrIyA176SPIlRkvxNFWB
+WLv0F3kfziSaSfeuACfNoS2PAZWYlHmcdQOPTegDOjeCTsbT8Minwvh5w6BUdnh
KOpPmdY+wdcUT9hZnvleS8E6pzS6nn7S28Yar1AB1hetdA+YuhNH59KZ/7NdkF3G
ev3YwLJH76gvv4T5opRyNbHU1dMimX3GbMYQIRtl1m6mbWmCBBepEChTrek0b1GG
1rQWkhqq90dC8sCa/aIsjXUzuvd+TSbDmXhOAL1eXdsKJsmdQTU6O4REk5zzaa73
SF3GcUhZKkS9ZLull/EjVpM0iE8Ay22nOCAKutAGRbGnu7R37OeedZUiDbh3L4KI
3kHgk1reDsM/YCqp0HDggWt8D5OqA4VvrShGORua2H1bRjK6bih6WNtz/54HG34b
qdfjjVOKZ014YPP6as790ukBJ91piDQUnk8o5sLYOz2LSfITe2PHVLzSuv8CLzCm
tkty+hV2SzVbLwcdnB+NZ6T+w1RpeuEJK+qFsKS+RBYInXWhftk+Y6OPxVeplYdK
/JsVq+pUCxKpx/mDSc0hXZOJsFPWJml9UMqx8Km94w0q3Rv33t7mvSzECAmK+1ty
PqoNcBdmxcPZvzKu0ZT3dwvbXHJDNYjl2HyKyp/6lmZD8aa/trz/iHcWM3GWPGEL
MgIEXOhAucIaPCdyKpFteRlCnttMg/LmsFdFMlRymUsXfR0nZhYeO56I4mB7kkBm
MfiVaRKvbqcEjjN+y7yOm4RepGayc8Pe1I7zp60WusdYusuRqOepznj/kPVnYJUq
ErO54geI0Uyihj1aroSG6h5v0uJL5AX3Lxol6yZaVkRGYrK6MCED9dyUjpDTFGEa
lrK74xABQAQB9UdSMXv7XSBCG9K/6mbhSBRVQXZp0v+z//MIhMBAlELwjDsh+Fwb
jusCT8y1ldsC32X1G1q8Hyu9nLLFXe3iiFohFf4UsHqbv8Hg+i2LCd7noLaqdiz6
wtCDiEoZwyZwbNunWDecf+KISNZ22pteEwHM7ww71jp884bFxO4mhLO2VM0jHMRX
u29N5UIeh1PpW0mowb6f6gD7tSULo4tQP3ROsNHgEjNGwpf66NOMO+XJ+1OtOsiB
IibMsGrXhMwjVFxeFJ7tlHbOFtKpSyKm94+FPdYf29huw9MuOsaP4A==
=CoeR
-----END PGP MESSAGE-----
'''.strip()



NF_PUB_KEY = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
hPs2g3E/E9/LIA8a8cMzKkp1VvdFwQ==
=dYxb
-----END PGP PUBLIC KEY BLOCK-----
'''.strip()

SOME_TEXT = 'You smell funny'

# import ASCII formatted private key
priv_key = pgpy.PGPKey()
priv_key.parse(KEY_PRIV)


# import ASCII formatted public key
pub_key = pgpy.PGPKey()
pub_key.parse(KEY_PUB)

pub_key.fingerprint == priv_key.fingerprint

print(priv_key.fingerprint)

msg = pgpy.PGPMessage.new(SOME_TEXT)
msg.message == SOME_TEXT

# binary message format
hexdump.hexdump(bytes(msg))

# roundtrip binary encode/decode works
bytes(msg) == bytes(pgpy.PGPMessage.from_blob(bytes(msg)))

# ascii message format
print(str(msg))

# roundtrip ASCII encode/decode works
str(msg) == str(pgpy.PGPMessage.from_blob(str(msg)))

msg |= priv_key.sign(msg)

# you must use the | operator to attach the signature.
# the following does NOT work:
#
#    signed_msg = priv_key.sign(msg)

print(str(msg))