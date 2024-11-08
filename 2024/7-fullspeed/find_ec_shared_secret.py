from sage.all import EllipticCurve
from sage.all import Qp
from sage.all import ZZ
from attacks.ecc import ecdsa_nonce_reuse
from attacks.ecc import frey_ruck_attack
from attacks.ecc import mov_attack
from attacks.ecc import parameter_recovery
from attacks.ecc import singular_curve
from attacks.ecc import smart_attack
# Import SageMath functions
from sage.all import *

# Define the field size q using the provided hexadecimal value
q = 0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd

# Define the coefficients a and b of the elliptic curve using the provided hexadecimal values
a = 0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
b = 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

# Define the finite field F_q
F = GF(q)

# Define the elliptic curve E: y^2 = x^3 + a*x + b over F_q
E = EllipticCurve(F, [a, b])

# Define the base point coordinates x_base and y_base
x_base = 0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
y_base = 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182

# Create the point P on the elliptic curve E using the coordinates x_base and y_base
G = E(x_base, y_base)

srv_x = 0xb3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06
srv_y = 0x85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb
srv_g = E(srv_x, srv_y)

cli_x = 0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499
cli_y = 0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15
cli_g = E(cli_x, cli_y)

# G2 = E(p_x, p_y)

def BSGS(G, PA, n, E):

    # Normally ceil(sqrt(n)) should work but for some reason some test cases break this
    M = ceil(sqrt(n)) + 1
    y = PA
    log_table = {}
    
    for j in range(M):
        log_table[j] = (j, j * G)

    inv = -M * G
    
    for i in range(M):
        for x in log_table:
            if log_table[x][1] == y:
                return i * M + log_table[x][0]
    
        y += inv
        
    return None


def pohlig_hellman_EC(G, PA, E, debug=True):
    """ Attempts to use Pohlig-Hellman to compute discrete logarithm of A = g^a mod p"""
    
    # This code is pretty clunky, naive, and unoptimized at the moment, but it works.

    n = E.order() 
    # factors = [p_i ^ e_i for (p_i, e_i) in factor(n)]
    factors = [35809, 46027, 56369, 57301, 65063, 111659, 113111,  707201073707405117370130031082007155142895998762294965153676442076542799542912293]
    crt_array = []

    if debug:
        print("[x] Factored #E(F_p) into %s" % factors)

    for p_i in factors:
        g_i = G * (n // p_i)
        h_i = PA * (n // p_i)
        x_i = BSGS(g_i, h_i, p_i, E)
        if debug and x_i != None:
            print("[x] Found discrete logarithm %d for factor %d" % (x_i, p_i))
            crt_array += [x_i]
        
        elif x_i == None:
            print("[] Did not find discrete logarithm for factor %d" % p_i)


    return crt(crt_array, factors)

# print(frey_ruck_attack.attack(G1,G2, 10,20))
# print(frey_ruck_attack.attack(G1,G2,100,200))

print(srv_g*168606034648973740214207039875253762473)
print(cli_g*168606034648973740214207039875253762473)

