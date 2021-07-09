from Crypto.Util.number import getPrime, inverse


# n = p * q
# e = 0x10001
# c = pow( m, e, n )
# phi = ( q - 1 ) * ( p - 1 )
# d = inverse( e, phi )
# m = pow( c, d, n )

n = 221
e = 37
c = 59
p, q = 13, 17 # prime factors of 221
phi = ( q - 1 ) * ( p - 1 )
d = inverse( e, phi )
m = pow( c, d, n )
print(m)
