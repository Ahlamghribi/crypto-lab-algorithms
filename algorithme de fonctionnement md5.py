import bitarray
from enum import Enum
from math import (
    floor,
    sin,
)
from bitarray import bitarray


class MD5Buffer(Enum):
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476




class MD5(object):
    _string = None
    _buffers = {
        MD5Buffer.A: MD5Buffer.A.value,
        MD5Buffer.B: MD5Buffer.B.value,
        MD5Buffer.C: MD5Buffer.C.value,
        MD5Buffer.D: MD5Buffer.D.value,
    }


    @staticmethod
    def modular_add(a, b):
        return (a + b) % pow(2, 32)


    @classmethod
    def hash(cls, string):
        cls._string = string


        preprocessed_bit_array = cls._step_2(cls._step_1())
        cls._step_3()
        cls._step_4(preprocessed_bit_array)
        return cls._step_5()


    @classmethod
    def _step_1(cls):
        # Convert the string to a bit array.
        bit_array = bitarray(endian="big")
        bit_array.frombytes(cls._string.encode("utf-8"))


        # Pad the string with a 1 bit and as many 0 bits required such that
        # the length of the bit array becomes congruent to 448 modulo 512.
        # Note that padding is always performed, even if the string's bit
        # length is already congruent to 448 modulo 512, which leads to a
        # new 512-bit message block.
        bit_array.append(1)
        while len(bit_array) % 512 != 448:
            bit_array.append(0)


        # For the remainder of the MD5 algorithm, all values are in
        # little endian, so transform the bit array to little endian.
        return bitarray(bit_array, endian="little")


    @classmethod
    def _step_2(cls, step_1_result):
        # Extend the result from step 1 with a 64-bit little endian
        # representation of the original message length (modulo 2^64).
        length = (len(cls._string) * 8) % pow(2, 64)
        length_bit_array = bitarray(endian="little")
        length_bit_array.frombytes(struct.pack("<Q", length))


        result = step_1_result.copy()
        result.extend(length_bit_array)
        return result


    @classmethod
    def _step_3(cls):
        # Initialize the buffers to their default values.
        for buffer_type in cls._buffers.keys():
            cls._buffers[buffer_type] = buffer_type.value


    @classmethod
    def _step_4(cls, step_2_result):
        # Define the four auxiliary functions that produce one 32-bit word.
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)


        # Define the left rotation function, which rotates `x` left `n` bits.
        rotate_left = lambda x, n: (x << n) | (x >> (32 - n))


        # Compute the T table from the sine function. Note that the
        # RFC starts at index 1, but we start at index 0.
        T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]


        # The total number of 32-bit words to process, N, is always a
        # multiple of 16.
        N = len(step_2_result) // 32


        # Process chunks of 512 bits.
        for chunk_index in range(N // 16):
            # Break the chunk into 16 words of 32 bits in list X.
            start = chunk_index * 512
            chunk = step_2_result[start:start + 512]
            X = [int.from_bytes(chunk[i * 32:(i + 1) * 32].tobytes(), byteorder="little") for i in range(16)]


            # Make shorthands for the buffers A, B, C and D.
            A = cls._buffers[MD5Buffer.A]
            B = cls._buffers[MD5Buffer.B]
            C = cls._buffers[MD5Buffer.C]
            D = cls._buffers[MD5Buffer.D]


            # Execute the four rounds with 16 operations each.
            for i in range(4 * 16):
                if 0 <= i <= 15:
                    k = i
                    s = [7, 12, 17, 22]
                    temp = F(B, C, D)
                elif 16 <= i <= 31:
                    k = ((5 * i) + 1) % 16
                    s = [5, 9, 14, 20]
                    temp = G(B, C, D)
                elif 32 <= i <= 47:
                    k = ((3 * i) + 5) % 16
                    s = [4, 11, 16, 23]
                    temp = H(B, C, D)
                elif 48 <= i <= 63:
                    k = (7 * i) % 16
                    s = [6, 10, 15, 21]
                    temp = I(B, C, D)


                # The MD5 algorithm uses modular addition.
                temp = cls.modular_add(temp, X[k])
                temp = cls.modular_add(temp, T[i])
                temp = cls.modular_add(temp, A)
                temp = rotate_left(temp, s[i % 4])
                temp = cls.modular_add(temp, B)


                # Swap the registers for the next operation.
                A = D
                D = C
                C = B
                B = temp


            # Update the buffers with the results from this chunk.
            cls._buffers[MD5Buffer.A] = cls.modular_add(cls._buffers[MD5Buffer.A], A)
            cls._buffers[MD5Buffer.B] = cls.modular_add(cls._buffers[MD5Buffer.B], B)
            cls._buffers[MD5Buffer.C] = cls.modular_add(cls._buffers[MD5Buffer.C], C)
            cls._buffers[MD5Buffer.D] = cls.modular_add(cls._buffers[MD5Buffer.D], D)


    @classmethod
    def _step_5(cls):
        # Convert the buffers
        A = int.from_bytes(cls._buffers[MD5Buffer.A].to_bytes(4, byteorder="big"), byteorder="little")
        B = int.from_bytes(cls._buffers[MD5Buffer.B].to_bytes(4, byteorder="big"), byteorder="little")
        C = int.from_bytes(cls._buffers[MD5Buffer.C].to_bytes(4, byteorder="big"), byteorder="little")
        D = int.from_bytes(cls._buffers[MD5Buffer.D].to_bytes(4, byteorder="big"), byteorder="little")


        # Output the buffers in lower-case hexadecimal format.
        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"