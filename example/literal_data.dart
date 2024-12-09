import 'dart:convert';

import 'package:dart_pg/dart_pg.dart';
import 'package:dart_pg/src/common/config.dart';
import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';

void main() {
  const passphrase = 'NU=WM<;ev3(^^M@)dIt,O|9k*<xLpv7v';
  const literalText = 'Hello Dart Privacy Guard :)';
  final password = Helper.generatePassword();
  final literalData = Helper.randomBytes(10000);

  const rsaKeyData = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

xcMFBGbzljMBCADB4KjKfIR4GshZ3cBQAXCZgKgGKl9p313/K88LjDEJ3MWUCx07ww+fZzmOXh2V
vIGPt/QwDuoHmFX3B/HCesK5aIbda9CuWZrt2srRBxO33PKYVbY/Fh3Z4OU/xOacB3mHEq/C/+H9
OIb3cl4heCrL9lmTy0SUIlGq3uCmWTskdyQUQtjVKsJ5TikjEsbDCrIRek+wBbqTyxj9RK0jTULf
SMTZmICvfDryOGSKTstwnvfWTDdR/++CSXTN10AxwPEwqYSrI1er19/VOAT3BKACrGJ080g3E/8j
H3gxfgQKBLYONfaFoqG6/GP0Bw1R3SywhoJcFXyttqPys3jyRLG5ABEBAAH+BwMIxgPhQuTOrrng
BH3m8yuBhDw4lhBkFDeu1nof+QO/ecEoeaChj3b7QjzksErgdQM4X0cOE2bXzx0Ipr6syAY2mB+0
XveEBz0VuF/Ep0hCcf+stie1vjhecztlQrW9Q1Z9d061joC/rF1xaPzGDEbaWgDsJXjWNJgilUkT
kBW8PLeS/AHFaDsSiiQlYJM9W8wdu0yGcP9Mgfur4R4ozFgm94kTZetBk8Fu1ys9LPzF6nraQDmq
SDamHm3MifBdStAG6cde7U5zfgLLFJXtJQR/qtJICDgltEfFC35n+Z32i4E6uwfDdQEySLSeuPuN
9Uv+0/avAC0zVpNE/0cQcIjuCIfu7ldO/0PVGvcJ/1I6zFKcXqlsNzzt4jCDEN6d8O/8182ySM5B
9eRUkxRgsnuwQNMNJS8EPYiMHWHEMCl8fjYBIEkVzrkIdSMy3wZ47AAMIJOPLw6XtixREtAI16pR
Ggt+BBjb60ziufTDJP/8TI7WCo6u2DOolr96kHp8yMYoT6GGCiNCRxk89x35GspEwaqtL6M+nhjH
rBpuKXY/Q76Uz9ohFQBu4JFDN0McP+/RLnqu1tYNLvaavZNxBefdF93TUSFxLjX6E0bH/akv7qjr
/HhZzzOItqXucQjP3ij0XmOfjpxYmASX884hpjGDIeeToKrsCH+zBHPFefEb82P33ZyS1inS8CoU
oeRa3+lFPCZ4+PLSzPEPf9P3cUYI0Oz5B0a1xkPJFCXNMsKwgE8281xIzku28ukNGEq+c/lrx93x
T/7jz4xfywqCDM1AGNgftg/bgO/2Rccg9AE4kE+mrt7cKVhzNqjqCg0o/2R72hy2zyItwYpcbzQy
gfZF7uZDbfsGHm7ahWc5ok11UhlHR5tb+TRblCOULw7ZHCJPX01FqpTCA6f8ZXCNVmvwGOE0jE3N
Kk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udjE5ODFAZ21haWwuY29tPsLAowQQAQgAVwUCZvOW
MxYhBLmq5GGR47m2np/UfQ+Bazb8iuUPCRAPgWs2/IrlDwIZASwUAAAAAAATABBzYWx0QHdlYm9m
dHJ1c3Qub3JnPgQ/T0olCxhJxKenOan/KAAA+d4IAA301RJ2TPumMumVmhAe61uYAh9YXWvycYyt
78PD5xmBJDAq34lo2x9QlSomCEpRn8t/QN7XJkgXE/y4ZCQw4pAKwSvfmHR2KX30k6pRf0CJwuJe
gIhBlHj2XjYLLyjW/6KsDNUyBOi3/de29IXZ7oNTlrQtioKlld0czanqU66rD/Y8GMybcL2n5v/f
YtcMntG79LlnCx5K+vtprwZMApBMUebaK3poryMFkQEvXYDbCOpuKBMUbMHdW+eCDVBqqoOc6KgC
O9gtzlghwO7hRcLI8O3uKMlMNHVSAf65cWSiKVIFPC/HmGW1UAlk6Lg9KkpaivFE9KQMb5l/Roy0
a9XNLE5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udkBpd2F5dmlldG5hbS5jb20+wsCgBBABCABU
BQJm85YzFiEEuarkYZHjubaen9R9D4FrNvyK5Q8JEA+Bazb8iuUPLBQAAAAAABMAEHNhbHRAd2Vi
b2Z0cnVzdC5vcmdn9NA28PRMXMWr1YGw/15rAAAigQgAvTY9LZ0UguUn4hOds21/RP0utAkCizUK
gv4VEW6KMR6Hm3yk5FrOckbWj1NLbpiZIG6xE4rery39sJ7nWqXqM7mpiMHUE1roxqlYYpIN4Dac
6uQ+PgzRs1xF9mm3M/y5jMGLYzk6MGHO5/fDA/IOEsVopMbMHMLTR2ClPXZKCqc7Iz1Nh5KyJ65k
OyxR628+zCTox4oX5LCD/gCQLdhLOITFL7Rx5ZTZ9kHW4D7xQqCo7Tblp6vPsE+QPJCAVxApiMCQ
j8wdBVnkjQneHxlEm1cOowjq/s6HP0V5ZQP8xiaIcYCL1/72FnZLP7KbAhKJT7l4XaI7dkzY9wji
hJGwPMfDBgRm85YzAQgAl/wbuoXKZ2mbltlSD6DF7ZUfNTO0yJ/+LWoMLGPLNOLWT6Msl40dfd3g
C3FJr2MAB0C50yJoW/RSxVLFf01ji0wbW1gjvgSR7tcUrel2e7qpltWAWBNsMHR9XYx5D7sOpXba
vkydg+rkocpNoaUXHRvLZ0OkWBuzJouqV5LJtGe4WdhBzWP32RGVKRSmeF0kDYgJvDCR46hCnnYl
z5nrujISvynRW3U70wiOgAixWeI1FrwHfK3LBnJIS8yoV0XgQhYXbLBfu7vs9WLoJU1Qc6mQYmUv
+tOPlSvmQuLbQv36DDoerebfSvRvxKE3BQ/p7kaeAQAXhkFWQF4zS7Ie/wARAQAB/gcDCDRZxh6o
WiSg4CqEIw68HEHxCjU7nuTnV1AAdYeMFqqY1qZ5uMGS+dwtolwAshInwcerawlmyPe/DQEC6GbT
6bT/1yQCRwqBxRQp4LX1i2YA7ewwkLxh2ool0LTgBeRQwyUhloeEM0JExIGbKuo+OR45UGGZQOxc
vyHaqeda/7APOgiSbBaJtTxWbsWkvIlz85H5GrXmBplikvh/jSHwqrZUGm0HxyzXgKRaGzUX+t15
4LDD5dPAChxWB8iZtGT4nHHgtoJLb1VA6bTER3CH3keCwH54Y0I0Jz8BwNKrFAwKfFXg1IbihOQj
Amfrz6aqIaaOu+S5gO1hrv3EXagAosPGgIh8Cnv8P6Ijae4Jdw+obdKP7dKZu8cT7thlQ+JEOGzK
L6wJoKxQeTo/jcZ/8BgRigZyjyyR15H4nlIZQVPXpkG+7TL86de9cfIKm40CIo694UeCItDipKSy
E6mEzQVU4ikHE0CAvzVDjJpbYhfOm2gKFrEWV+P+5qoFqUdEnbESoyk8OieRkxn+tm1g1Xdtc+t0
IifNdIomhjxpEbQLPcY45HftXf0Ly+tXykWsFuwFfjEYCX8+sHTCLRcQG5dfE8JdUtqtJH7ai1PF
dZ/8jPptOWmOnpQ9PedPA1KbT6DYi2iIIDzVxSEmrvfA8FE43JIURJWXJe6iA3qGnEvKudModgN0
8Hwgm2HJYpwY6hWQZHL+K1m7r9h5DFejRWYn4hSelFfXdbTaLw4OVwt2xqrtESzOrcSSqEtTrW1b
qeVrVvfgInGWI4gEpGj8ldEjD76/0jel79/o0tqOAnNNat1qvKU36UuOgu9fQhTwfmpswmX6o/NW
Z5RVZINstIyL+KCSEZs35MsjqUmiBqvfXDcmgAim+Wg1D6T9osI2oAW5hDDQ51FNx+gXMcm51pmA
Udt4bsLAowQYAQgAVwUCZvOWMxYhBLmq5GGR47m2np/UfQ+Bazb8iuUPCRAPgWs2/IrlDwIbDCwU
AAAAAAATABBzYWx0QHdlYm9mdHJ1c3Qub3JnWABE9JWruOSriXq9STSKhwAAE30IAAnAkdIJ2U4U
RwCIQB5Ay9l/taWaswgoaUbibHHXVQLGo//rdA2mJDGi9OE+PdD/oHqvsZ9ZZzVGPNvSgryfTu9x
yOBaW/H0ixfSBu7FQiZImCmUYX/uVIRgZjGkJpN7ul3cMNr6ailJNGMmb5mS4iDNm9aasRKT6TLJ
jV5mnBI9MZ4++ArhimXGGSqPFokbbIAhVbCNQgVcPo1YHvgH10/fWki42/YwQzGfdUxpjOYEgAqY
RfHQZ+LpJzTffMAp7rdge5H4pgDPBiV1744HMnVwwrN2g+bMM1+p5MRW9U0p/f0VzOp6iKBfDKiQ
mNqrM25q1P8rBo69xZErGjQ/nFY=
=HDCL
-----END PGP PRIVATE KEY BLOCK-----
''';

  const eccKeyData = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

xcBHBGbzljQTBSuBBAAjBCMEAbbJmwFEE6Mwhn/S9gFoSwnY2vj9iPDA9ooNtKdg5BqL0A3fQ0y+
+zG4pu/YtGiQwjbrZiyWqAipcPH7w/3q88RkADcqkIjBreSHhVspX5CiL3RBmrqBXzo4L+xZ1ejj
Q9Us26FSo+/1vC6/eFEDJsZMuqWycwf9qMLn5E2pwyLpYbEG/gcDCKRFCa2HQxKc4IKYY9SsedM+
lyDojXJojmJu3q/x7qWof5HC4jgKbPIjoy75c7QqzRD1IgOmIkEabiniFrwpopyuM/mrSGo1XghD
C6eq9YP2+hWFfxyXul89/3teRc9FDgk4EHw53KlBNFRW7FUh60zNKk5ndXllbiBWYW4gTmd1eWVu
IDxuZ3V5ZW5udjE5ODFAZ21haWwuY29tPsLAOAQQEwoAZwUCZvOWNBYhBOa5LKMYZwD9HaNB23w/
10k1r0M/CRB8P9dJNa9DPwIZATwUAAAAAAATACBzYWx0QHdlYm9mdHJ1c3Qub3Jnv5XY7w0YN3Dm
LyrrylzmJv5kHQnvFWStpM399axg7jUAAAHJAgjaA/1/Fd4KqvVY7IPst9b2tmgp4gRkmz9s2Cz9
fyfLK50mvkZg4eCzuNBUZLeu9iZlalzE/KuQNpH784mKb7+MfQIJAdGQljsZNCDhqUM9DAxv1jYb
6aeFH6ohj0lBItWSd73f2sXdsWAs6KQcauPHcq7cgBk/KLK0+gBgPalm7w2cPfZ9zSxOZ3V5ZW4g
VmFuIE5ndXllbiA8bmd1eWVubnZAaXdheXZpZXRuYW0uY29tPsLANQQQEwoAZAUCZvOWNBYhBOa5
LKMYZwD9HaNB23w/10k1r0M/CRB8P9dJNa9DPzwUAAAAAAATACBzYWx0QHdlYm9mdHJ1c3Qub3Jn
oZ5uzew0qePaYSRE5PVTZ/0Ln9eDeyDOgu0K6lotELcAANeOAgkBN9lY8GA8qch5gZFfLK7LgVb3
xboQXXVomecoH+XyQr+rHT8+2J+TuMgPToW76U8GFCB9aK3Q9hJw4DjB0L0pRD0CB3lxq0ux6Lbq
PH1T9vFqTZjdHDJLBULh5C32tVT1NEJ2jCEf6h2/SiUg31zyU2aAi3hpJwyz6xbyevimNwVA6H9a
x8BLBGbzljQSBSuBBAAjBCMEAVGNA6F9Bi3jc4l8XwZW3hI80CJzfDQ0Wil4TpSYNNZ/tXkkm0Ze
BmtM9T1inKe26bha/BP4bqTJCEv9XdIS0Lx/AEyO7naiRvGjxMMtXasRxYF+hyQss2fvf8SRc6pf
yGFpZ6s4pwrdvxU5X5LJ0lm4If387vEGeMj9c5QT/tSkQKRIAwAKCf4HAwjITvsdedZLjuB5dj7d
CSlR/Mn3gy7cRW8OTO4qq34soWeNKAYklCVqlpCoRDCsxVVVVj/Bbl2GPyeYMuK3e4nEQw2mS/VP
Y+Fm1neFFRKe77/snn1j5pQVAbdWmtGnbG8CyESu3nAMl1O/Am8KJzqVwsA4BBgTCgBnBQJm85Y0
FiEE5rksoxhnAP0do0HbfD/XSTWvQz8JEHw/10k1r0M/AhsMPBQAAAAAABMAIHNhbHRAd2Vib2Z0
cnVzdC5vcmeoj6/2jTLHZGEC/Wwn5Pp8NcxrkV/CePcQVk9e8vzSPgAAibsCCQG6tZ3tj6FRxz7t
JwVVg+CqVCTjqLGuKzWIveE5d9Aot4V5bREhZDOzZ7Umgui0Al3qME6Ieuar+Wy1oGeoEOoI1gII
xeYCguecLORImgm91Cg3iCZr/apVKjt5muGW+b9DRe5dNevmEvzbcvzzvYfeN1skZ+05rWGsTmzD
xkqGItNj3gs=
=pP8r
-----END PGP PRIVATE KEY BLOCK-----
''';

  const curve25519KeyData = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

xX0GZvOWNBsAAAAgsDfIqP0lv8+V4Eaj0omfm+FPDcMeVeEak7qabHd/pcn+HQcLAwhRaGxMbGEj
KeAjp9Kh/3vzuZ8Xfdj8w8je6o5USELRl4rD0RO3MDrppA2pfRbSp1kn/Xvfuzggou+s4l++cR37
lhNdXvBbII6xt7jNLsK7Bh8bCAAAAFwFAmbzljQiIQYxez29s+qCzXaa8BXQ2poBMBS0F8Z3FlfC
DS7WrX0cWAkQMXs9vbPqgs0CGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJ
AwAAAABxRRA4Q3rcJQpPHJl6e4RfQcwnQYeZJr9JBOpQtSRAHvqhwbgs0UbotyXhqHKGyc5TZpz/
XpJ1GefK5/8ex+aralEP1QB38XSiYQiCI1jIocL1DM0qTmd1eWVuIFZhbiBOZ3V5ZW4gPG5ndXll
bm52MTk4MUBnbWFpbC5jb20+wr4GEBsIAAAAXwUCZvOWNCIhBjF7Pb2z6oLNdprwFdDamgEwFLQX
xncWV8INLtatfRxYCRAxez29s+qCzQIbAwMLBwkEIgECAwUVCAwKDgUWAAECAwIeCw0nBwEJAQcC
CQIHAwkDAhkBAAAAAEz9EDqXl30gpjVoykzq5Ja7YWxpoNmTEOO1CpVhAEPL6KQe3g+2/bjROoAq
nj8tI235RVUHLH1bvYIjWaG1ZvT2bcDfokqkSSyIM/yUpM+8tfYIzSxOZ3V5ZW4gVmFuIE5ndXll
biA8bmd1eWVubnZAaXdheXZpZXRuYW0uY29tPsK7BhAbCAAAAFwFAmbzljQiIQYxez29s+qCzXaa
8BXQ2poBMBS0F8Z3FlfCDS7WrX0cWAkQMXs9vbPqgs0CGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMC
HgsNJwcBCQEHAgkCBwMJAwAAAAALWRA0hBEpX2BpiC0qnGu4R7JSy1iEecTkOGxlybUmmDdz3yGg
gr7wwHUdJwVRCmAac9jt7ZncLEHfn24LtXAI2CbGnw9mx8jvIvQeXk/I5EyvAcd9BmbzljQZAAAA
IFXT+LS94i+Wg30HgPLW1hXpLRR+ZylJ46nLHPYuzVEq/h0HCwMITUh5JLzx32DgNavoHwOsWoAd
gQnDQNIwjX/6sHj4WtEg9IBz9LmFT9angnY7QoOPHBunvuX+TZmu0XC2bxLzqEYV+NqqqylJ3yv7
YTbClQYYGwgAAAA2BQJm85Y0IiEGMXs9vbPqgs12mvAV0NqaATAUtBfGdxZXwg0u1q19HFgJEDF7
Pb2z6oLNAhsMAAAAAKL3EF1yfJE4NDbzPdNHggwPZheJUksDHwdk+/JGMrBf98H47Ql+8/PWpyi4
j6vVjpvxh/UIcVeMzVpMehALapXO3ddXOZCdCTXd8PqXe7gv6xoE1RNs/79ptV0jPLqXodandB+z
VS4W
=oH6u
-----END PGP PRIVATE KEY BLOCK-----
''';

  const curve448KeyData = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

xa8GZvOWNRwAAAA5EN1vmT1zBRrWb3u7WplWBLMom6ou9KLfVMa+qHNqAEGlyiBr3ik4wD8UOO8t
ETP76oGUaeS5PXaA/h0HCwMI7kHpr3/alWrgIY5ni6U2mqvWywD89BwZpx+Npit0FTmE/XzIxX+Z
44XjKQkV0qGY+KEBG65VPYNHiDTDRzne5sfigHQkbkKMrt+4edgm0PGRytC0V49zE4Bhiql/ONps
EVwknbivwsA9Bh8cCgAAAFwFAmbzljUiIQYAEjmqCUOtK+AiPLXUQ+KiNLKdrnxoTu7yaXKnfHG9
dQkQABI5qglDrSsCGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJAwAAAACq
iiALAPu5JW/ugTbNS5AljXIZmU0N4DI1H9KW07V6Q0FwcEGLUE8XIcjVwYE/d40kjBlwjcj1miDp
tkDSxrGWJtxWLdwwaXsH00Q1KuNWE/dYziZj7yqwziusAFVT/0NDvMlAfKE/jaBRDx+7u4CrUXOQ
STj1HD+0MtWzICEYDhVO0D3AxcJzu0zlHiqvqG2pzd8wAM0qTmd1eWVuIFZhbiBOZ3V5ZW4gPG5n
dXllbm52MTk4MUBnbWFpbC5jb20+wsBABhAcCgAAAF8FAmbzljUiIQYAEjmqCUOtK+AiPLXUQ+Ki
NLKdrnxoTu7yaXKnfHG9dQkQABI5qglDrSsCGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcB
CQEHAgkCBwMJAwIZAQAAAAChWiD9MzgR4vG92un0Tb7pCoVpI/bE01e6cHW9RdxhrMdz3mv9jY5r
/YYvzxwDUjvONRNqoNsxuiLWVJZBmdxO0sFuLYGCPra5HselHX4d1SfmJjDl6AI6hXa/APfB/1ad
8EaFED2lXqwFyjUoiyW32fikMDK7XKYhgFQFV5qVCUXsQYoGa6IB55EyQk7lbFDF2uQPAM0sTmd1
eWVuIFZhbiBOZ3V5ZW4gPG5ndXllbm52QGl3YXl2aWV0bmFtLmNvbT7CwD0GEBwKAAAAXAUCZvOW
NSIhBgASOaoJQ60r4CI8tdRD4qI0sp2ufGhO7vJpcqd8cb11CRAAEjmqCUOtKwIbAwMLBwkEIgEC
AwUVCAwKDgUWAAECAwIeCw0nBwEJAQcCCQIHAwkDAAAAANEAIJMO5Ms4YHjwgJi/VR2vUexGYQ+V
UjiJ8Zoc51OLElncNoV3iHGKh8MQ/Uk1YFTvGux1Oj+YUrda6aMQxKbo52QqW7smBy4AaRb14KbR
ECTTpanGATQlBpUAw48dDb/WXvTBk4o9vSXea+szuOjIMHcHXzLpF5JncyZa4heK5WK+Hg1AcG7J
qSWUZgXZ0bRrqw0Ax60GZvOWNRoAAAA4Vpw0JybXe1syUb5zIG1wnqoKQ/mLjhpRFiXhLV4xGxpq
LP18Qs3sMBRYDLW2Ry142UWY6eEMhTz+HQcLAwi8WEJC2H4an+DOro/0ezMlHYoVtPKUagmEdHsB
2d1bKEm1QkNcbCYHhNetgSQuaWxuwVNjILnmERvv68Xe2Robu3a0VxrI0pyWJ4b9OeJytY77ABFI
AUchhdYv/+ETS0IWs/dQrMLAFwYYHAoAAAA2BQJm85Y1IiEGABI5qglDrSvgIjy11EPiojSyna58
aE7u8mlyp3xxvXUJEAASOaoJQ60rAhsMAAAAAOpQIMS3qdoWsevaHDU+d3ayQ7r9Q84usVFmlcBW
xnSxsrlOr7VznG2LoPsByEciV0utFmZ9IL2E/pT+jbE/ca4C1GBmIT4c8RVi874rSLbNyd4Qif6+
drWfih0AK7eJiDpDvBGMiQNrwaZtiNgyXKGCw+ephsZG+O0vGX4Q7a8jtkRUrI8hBtNrk9uVu6K5
dYZIvg0A1SCEq4w8mfkSbFRJrixxFabTL7COFHgvL25joDV8UIvxYg==
=aUu5
-----END PGP PRIVATE KEY BLOCK-----
''';

  final rsaPrivateKey = OpenPGP.decryptPrivateKey(
    rsaKeyData,
    passphrase,
  );
  final eccPrivateKey = OpenPGP.decryptPrivateKey(
    eccKeyData,
    passphrase,
  );
  final curve25519PrivateKey = OpenPGP.decryptPrivateKey(
    curve25519KeyData,
    passphrase,
  );
  final curve448PrivateKey = OpenPGP.decryptPrivateKey(
    curve448KeyData,
    passphrase,
  );

  print('Encrypt literal text message with password:');
  var encryptedMessage = OpenPGP.encryptCleartext(
    literalText,
    passwords: [password],
  );
  var armored = encryptedMessage.armor();
  print(armored);
  print('Decrypt with password:');
  var literalMessage = OpenPGP.decrypt(armored, passwords: [password]);
  print(utf8.decode(literalMessage.literalData.binary));

  print('\nSign & encrypt literal data message:');
  encryptedMessage = OpenPGP.encryptBinaryData(
    literalData,
    encryptionKeys: [
      rsaPrivateKey.publicKey,
      eccPrivateKey.publicKey,
    ],
    passwords: [password],
    signingKeys: [
      rsaPrivateKey,
      eccPrivateKey,
      curve25519PrivateKey,
      curve448PrivateKey,
    ],
  );
  armored = encryptedMessage.armor();
  print(armored);

  print('\nDecrypt with passphrase & verify signatures:');
  literalMessage = OpenPGP.decrypt(armored, passwords: [password]);
  var verifications = literalMessage.verify([
    rsaPrivateKey.publicKey,
    eccPrivateKey.publicKey,
    curve25519PrivateKey.publicKey,
    curve448PrivateKey.publicKey,
  ]);
  for (final verification in verifications) {
    print('Key ID: ${verification.keyID.toHexadecimal()}');
    print('Signature is verified: ${verification.isVerified}');
    print('Verification error: ${verification.verificationError}');
  }

  print('\nDecrypt with rsa key & verify signatures:');
  literalMessage = OpenPGP.decrypt(armored, decryptionKeys: [rsaPrivateKey]);
  verifications = literalMessage.verify([
    rsaPrivateKey.publicKey,
    eccPrivateKey.publicKey,
    curve25519PrivateKey.publicKey,
    curve448PrivateKey.publicKey,
  ]);
  for (final verification in verifications) {
    print('Key ID: ${verification.keyID.toHexadecimal()}');
    print('Signature is verified: ${verification.isVerified}');
    print('Verification error: ${verification.verificationError}');
  }

  print('\nDecrypt with ecc key & verify signatures:');
  literalMessage = OpenPGP.decrypt(armored, decryptionKeys: [eccPrivateKey]);
  verifications = literalMessage.verify([
    rsaPrivateKey.publicKey,
    eccPrivateKey.publicKey,
    curve25519PrivateKey.publicKey,
    curve448PrivateKey.publicKey,
  ]);
  for (final verification in verifications) {
    print('Key ID: ${verification.keyID.toHexadecimal()}');
    print('Signature is verified: ${verification.isVerified}');
    print('Verification error: ${verification.verificationError}');
  }

  print('\nSign & encrypt literal data message with AEAD AES256 cipher:');
  Config.aeadProtect = true;
  encryptedMessage = OpenPGP.encryptBinaryData(
    literalData,
    encryptionKeys: [
      curve25519PrivateKey.publicKey,
      curve448PrivateKey.publicKey,
    ],
    passwords: [password],
    signingKeys: [
      rsaPrivateKey,
      eccPrivateKey,
      curve25519PrivateKey,
      curve448PrivateKey,
    ],
    symmetric: SymmetricAlgorithm.aes256,
  );
  Config.aeadProtect = false;
  armored = encryptedMessage.armor();

  print('\nDecrypt with password & verify signatures:');
  literalMessage = OpenPGP.decrypt(armored, passwords: [password]);
  verifications = literalMessage.verify([
    rsaPrivateKey.publicKey,
    eccPrivateKey.publicKey,
    curve25519PrivateKey.publicKey,
    curve448PrivateKey.publicKey,
  ]);
  for (final verification in verifications) {
    print('Key ID: ${verification.keyID.toHexadecimal()}');
    print('Signature is verified: ${verification.isVerified}');
    print('Verification error: ${verification.verificationError}');
  }

  print('\nDecrypt with curve25519 key & verify signatures:');
  literalMessage = OpenPGP.decrypt(armored, decryptionKeys: [curve25519PrivateKey]);
  verifications = literalMessage.verify([
    rsaPrivateKey.publicKey,
    eccPrivateKey.publicKey,
    curve25519PrivateKey.publicKey,
    curve448PrivateKey.publicKey,
  ]);
  for (final verification in verifications) {
    print('Key ID: ${verification.keyID.toHexadecimal()}');
    print('Signature is verified: ${verification.isVerified}');
    print('Verification error: ${verification.verificationError}');
  }

  print('\nDecrypt with curve448 & verify signatures:');
  literalMessage = OpenPGP.decrypt(armored, decryptionKeys: [curve448PrivateKey]);
  verifications = literalMessage.verify([
    rsaPrivateKey.publicKey,
    eccPrivateKey.publicKey,
    curve25519PrivateKey.publicKey,
    curve448PrivateKey.publicKey,
  ]);
  for (final verification in verifications) {
    print('Key ID: ${verification.keyID.toHexadecimal()}');
    print('Signature is verified: ${verification.isVerified}');
    print('Verification error: ${verification.verificationError}');
  }
}
