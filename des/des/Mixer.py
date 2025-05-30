from utils import *
from PBox import PBox
from SBox import SBox


class Mixer:
    def __init__(self, key: int, func=lambda a, b: a ^ b, block_size=64,
                 initial_permutation=None, final_permutation=None,
                 substitutions: list = None, substitution_block_size=6):
        self.func = func
        self.block_size = block_size
        self.initial_permutation = PBox.identity(block_size // 2) if initial_permutation is None else initial_permutation
        self.final_permutation = PBox.identity(block_size // 2) if final_permutation is None else final_permutation
        self.substitutions = SBox.des_single_round_substitutions() if substitutions is None else substitutions
        self.substitution_block_size = substitution_block_size
        self.key = key

    def encrypt(self, binary: str) -> str:
        print(f"\n=== Feistel Round ===")
        print(f"Input binary: {binary}")
        
        # Split into left and right halves
        l, r = binary[0: self.block_size // 2], binary[self.block_size // 2:]
        print(f"Left half: {l}")
        print(f"Right half: {r}")
        
        # Expansion PBox (32 bits -> 48 bits)
        r1: str = self.initial_permutation.permutate(r)
        print(f"After expansion: {r1}")
        print(f"Expansion length: {len(r1)} bits")
        
        # XOR with key
        r2: str = int_to_bin(self.func(int(r1, base=2), self.key), block_size=self.initial_permutation.out_degree)
        print(f"After XOR with key: {r2}")
        
        # S-box substitution
        r3: str = ''
        for i in range(len(self.substitutions)):
            block: str = r2[i * self.substitution_block_size: (i + 1) * self.substitution_block_size]
            substituted = self.substitutions[i](block)
            print(f"S-box {i+1} input: {block} -> output: {substituted}")
            r3 += substituted
        print(f"After S-boxes: {r3}")
        print(f"S-box output length: {len(r3)} bits")
        
        # Final permutation
        r3: str = self.final_permutation.permutate(r3)
        print(f"After final permutation: {r3}")
        
        # XOR with left half
        l_new = int_to_bin(int(l, base=2) ^ int(r3, base=2), block_size=self.block_size // 2)
        print(f"New left half: {l_new}")
        
        # Combine and return
        result = l_new + r
        print(f"Final result: {result}")
        return result

    def decrypt(self, binary: str) -> str:
        return self.encrypt(binary)

    @staticmethod
    def des_mixer(key: int):
        return Mixer(
          key=key,
          initial_permutation=PBox.des_single_round_expansion(),
          final_permutation=PBox.des_single_round_final(),
          func=lambda a, b: a ^ b
        )