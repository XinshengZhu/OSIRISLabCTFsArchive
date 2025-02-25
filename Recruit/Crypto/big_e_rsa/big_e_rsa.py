import gmpy2

# Since e is large, we can try Wiener's attack
e = 0x5f59fae794e08214ce3b07c5df03a7ba4fc82bf39b287f77bf4502ef8b5bb4bfdbbe7705e5fbc77468d630ffe1ab1f3a692eb17d8ad947d80e2f5b0a292eb99059bac84327bb454a6c21554135a82997c27d39c4059420bc3c87fa477160243a5213699ff5bc324504a1a9b914bf64e9963804ecbce77d0638fc212b6f76f00c7ff772cf2f294d303639a4a701e7618319c1724a4f8aa7060ff3eec4e9bd4fff9869aee0be8725773e59db3c9aabfd55044092254fe20e1d3db3e7e69907db7153a8dae65663ad44901131f33a612e7189876fca6aa3f2737cc63cbd2648bff4aaa842d880fd8fe395a19ce9d2b69ff151d0511231411bce6a1b3cd0e1d1b411de874f23dc146651c5b026598bf08a3cdf1e9c51ae91486823dfd2bae5db0dc53b3906dee7cbfd6e1509d2ff16f7df00a28e2b00adb9b315ea0485acc54ea0e68503835c03cf722306436d3d1db1688fa853f9d19ee4073701c823acbb3d51f9a89a7c13e4ed01b45416774fb80c14b05d44a687b608bc773cc12761a6f60778c7a24b59d5cf284be266b45345fec2ff793cc710bb32b499ff1a25df4d991058a2f3ac7432139d336fa2f29387d4916f21899966c509c62bb8e0006e0bb2927355a6e2db7913f675446f53320055cec1a0168b817ee46676730dd7576c281c287e68c8474f35ca7186d039666618b7f9dc1d664d5c7440aaad63709cbca86ea9
n = 0x88580a3dc918576306e8890cfd9cc2d5433c3cf29b49dc49a78a89c661b55e01cd210dbc9c6cf291645e7e970ed01090604cd39fe2fe58506b8d0eae7b1ed49cbf54f5fefbc07711e3196a890190e67abc72edb6e790759c377438cffac5081e4947bb9b91b88a091924e4e8aee54b39b00ee5b69b0b1ecd69875aaabad362cc7674f6f032cef1cdf63c59c059ce46501a63913a237370472d037345c84d7ddfcbdc67bf53ebe4660ea1042fa4cda86fac8fc2fe9bffd519769790d71d2182914bca64bf24917d33411eb41cbbcf1916a626cde16a8e7840a742fecbb292c40c30e3b20d981c3353706476b8dddbbe1cf9e77933d73e8bf56bab6df9362a72fc834e92d73e32a1871857752732fab5dafb33b8442a9a3b0898d225dbf2ddcd19f814c57a4d68d5b7301e4626b1a48cf3c24d3318557d1994296fb8dbbabd122c4387f7ae88fdc7617f22decdfb5bff4a45b0947a163f776a58f004c69213baf78ebed6aa3cc70bf3129fcfaf93f63786806354d7f7ed58f710fdc33d3058ec5e9be3993df2cca90e1f4915c422122103f587505c6a174c06aadd2ca0b78afdaa741768ee10af0a6b27d6828ccde713972169cf8fee443eb08237d068f598ce3440c3ea17dff1d393ebe7386c6259921af6740d79a478a0e0c2a647e1db6d27a7b76bdd9c50d0d8895594955253a5479e45e01683e9c65b9ea31fcfefba63ee0f
c = 0x22724fec771e783721983db34cb3c47b6f5e7cfe0aae54cedcff0dec8c3b80897e00486b1888e6cf7aeb94e8721c8d1b6857019b33ea0c3226dba9d86b0c72f140c28e77304abb2bf0a78423fe7d41da24e4fac5a59a03b58f7c2adf2f82c397423257a53696922980fe1d1aa77904c2299ebcb168208e0e1c87fd3bec84daf3f99c4745cc9eaea7379058bd02b73ccd9139c4764a4be06bef283ee2596fe2519f22d5965f2607c7acbf83b2ce84f079e2d05e7d2a84b5c99f8e6bef57a67ab865ac2714481cdd015b1f1b90570fb847d571887c865b3d55ff3ad360e13880dfe298c82be6643bda99e379c64e1cf5cc809d48065c7577d947c909f755337dc30fa79979b7ffc1176310b89f75acc4cedc803466addff565370bcb5b81d99e0ec5cbebdcc61cddc305908a4dc15d869c6083206537d7e2d0875c276191d709aaec1ae838d6c2ed4d3a006915e345ea0f2f37f7ed5d6019d2d74a8cdc86872808104e2607fb8fea64288151868cff50bae450e162ec7adf2e98148e63992ed6c92d8aafa1bf8b398493ca9ef78531963af65a70c7a65756501fc951321b5a1425549d1933eb3615b2dcee5620c5ea7018f2557f283b7820d4349d9b5112731760863a177f3ee7660c3d7ea82be13c6461d2ae89c416ed6492048620f0e0527f808a7f9e802c4d9d4b9f880327693c4f8b443de2dc703a4cfcb2e57a685afb73eb

def continued_fraction(n, d):
    fractions = []
    while d:
        a = n // d
        fractions.append(a)
        n, d = d, n % d
    return fractions

def convergents(fractions):
    n = []
    d = []
    for i in range(len(fractions)):
        if i == 0:
            ni = fractions[i]
            di = 1
        elif i == 1:
            ni = fractions[i] * fractions[i-1] + 1
            di = fractions[i]
        else:
            ni = fractions[i] * n[i-1] + n[i-2]
            di = fractions[i] * d[i-1] + d[i-2]
        n.append(ni)
        d.append(di)
        yield (ni, di)

def wiener_attack(e, n):
    fractions = continued_fraction(e, n)
    for k, d in convergents(fractions):
        if k == 0:
            continue
        phi = (e*d - 1) // k
        # Check if phi is valid
        a = 1
        b = -(n - phi + 1)
        c = n
        disc = b*b - 4*a*c
        if disc < 0:
            continue
        root = gmpy2.isqrt(disc)
        if root*root != disc:
            continue
        # p and q are the roots of the quadratic equation
        p = (-b + root) // (2*a)
        q = (-b - root) // (2*a)
        if p*q == n:
            return d

# Get private key d using Wiener's attack
d = wiener_attack(e, n)

# Decrypt the message
m = pow(c, d, n)

# Convert to bytes and decode
try:
    plaintext = bytes.fromhex(hex(m)[2:]).decode()
    print(plaintext)
except:
    print("Decryption failed")

# flag{small_d_wait_why_are_u_laughing}
