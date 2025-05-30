p = 17  # Corps fini ℤ/17ℤ

class ECCPoint:
    def __init__(self, x, y, a, b):
        self.x = x
        self.y = y
        self.a = a
        self.b = b

    def __eq__(self, other):
        return (self.x, self.y, self.a, self.b) == (other.x, other.y, other.a, other.b)

    def __str__(self):
        if self.x is None:
            return "Point at Infinity"
        return f"({self.x}, {self.y})"

    def is_valid_curve(self):
        return (4 * self.a**3 + 27 * self.b**2) % p != 0

    def is_on_curve(self):
        if self.x is None:
            return True
        return (self.y**2) % p == (self.x**3 + self.a * self.x + self.b) % p

    def inverse_mod(self, x):
        return pow(x, p - 2, p)  # Fermat's little theorem (p is prime)

    def add(self, other):
        if self.x is None:
            return other
        if other.x is None:
            return self

        if self.x == other.x and (self.y != other.y or self.y == 0):
            return ECCPoint(None, None, self.a, self.b)  # Point at infinity

        if self.x == other.x and self.y == other.y:
            # Point doubling
            slope = (3 * self.x**2 + self.a) * self.inverse_mod(2 * self.y)
        else:
            # Point addition
            slope = (other.y - self.y) * self.inverse_mod(other.x - self.x)

        slope %= p
        x3 = (slope**2 - self.x - other.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return ECCPoint(x3, y3, self.a, self.b)

    def scalar_multiply(self, k):
        result = ECCPoint(None, None, self.a, self.b)  # point à l'infini
        addend = self

        while k:
            if k & 1:
                result = result.add(addend)
            addend = addend.add(addend)
            k >>= 1

        return result

def DH_key_exchange(base_point, priv_A, priv_B):
    pub_A = base_point.scalar_multiply(priv_A)
    pub_B = base_point.scalar_multiply(priv_B)

    shared_A = pub_B.scalar_multiply(priv_A)
    shared_B = pub_A.scalar_multiply(priv_B)

    return pub_A, pub_B, shared_A, shared_B

def print_menu():
    print("\nMenu:")
    print("1. Vérifier la validité de la courbe")
    print("2. Vérifier si un point est sur la courbe")
    print("3. Échange de clé Diffie-Hellman (ECC)")
    print("4. Quitter")

if __name__ == "__main__":
    # Courbe elliptique y² = x³ + ax + b mod p
    a, b = 2, 2
    base_point = ECCPoint(5, 1, a, b)

    while True:
        print_menu()
        choice = input("Choix (1-4) : ")

        if choice == "1":
            curve = ECCPoint(0, 0, a, b)
            print("Courbe valide ?" , curve.is_valid_curve())
        elif choice == "2":
            print("Point de base :", base_point)
            print("Sur la courbe ?", base_point.is_on_curve())
        elif choice == "3":
            priv_A = int(input("Clé privée A : "))
            priv_B = int(input("Clé privée B : "))
            pub_A, pub_B, shared_A, shared_B = DH_key_exchange(base_point, priv_A, priv_B)
            print("Clé publique A :", pub_A)
            print("Clé publique B :", pub_B)
            print("Clé partagée (A) :", shared_A)
            print("Clé partagée (B) :", shared_B)
            print("Clé identique ?" , shared_A == shared_B)
        elif choice == "4":
            print("Fermeture du programme.")
            break
        else:
            print("Choix invalide.")