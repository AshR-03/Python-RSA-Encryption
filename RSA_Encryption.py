
# 1) Use a trapdoor function (Simple to compute in 1 direction but almost impossible to compute in the other)
# E.G 907 & 773 make 701,111 [2048-Bit RSA have 617 digit primes].

# 2) Algorithms like the Rabin-Miller primality test to find decent prime numbers to compute the PUBLIC KEY.

# 3) Calculate Modulus (n) by doing p * q
# E.G 907 * 773 = 701,111

# 4) use Carmichael’s totient function. [λ(p*q) = lcm (p − 1, q − 1)]
# E.G λ(701,111) = Lowest_Common_Multiple (906, 772) = 349,716

# 5) Create Public Key using a prime number e, and the modulus n
# e can be any number between 1 and λ(p*q). Doesn't have to be RANDOM because the key is PUBLIC.
# For large primes, e is generally set to 65537. (Large values of e can make the code easier to decrypt).
# E.G e = 11

# 6) Let c = Encrypted message. c = CharacterInASCII^e % 701,111
# E.G let our message be "4" c = 4^11 % 701,111 => c = 4,194,304 % 701,111

# 7) Calculate C.
# E.G our encrypted value is 688749 (ciphertext)

# 8) Create private key d by using the key pairs. d = Inverse% (e & λ(p*q))
# E.G d = Inverse% (11 & 349,716)
# Use the Extended Euclidean Algorithm to find the inverse modulus of the 2 numbers.
# E.G d = 254,339

# 9) Receiver with private key computes with formula: m = c^d % n
# E.G m = 688,749^254,339 % 701,111.
# This gets us our message.

## Hashing the message ##

# 1) To create a hash value for a program or file, there needs to be a specific hash function to create the value.
# Examples of hash functions used, MD4, MD5, SHA-1, SHA-2, SHA-3.
# Older hash functions have been considered broken due to hash collisions which ruin the credibility of the algorithm.

# SHA-256 Process:
# 2) Convert the encrypted number to bits, add padding so that the length of the bits is 512 - 64. Padding starts with 1

# 3) Calculate modulus of ciphered message. This 64 bit value will be the final 64 bits to get 512 bits in total.
#    OR
#    Calculate the Big-endian integer which is the length of the text IN BINARY.

# 4) Initialize the list of buffers to create a buffers list. (8 Hash values defined in code). H Values = First 32 Bits of the fractional parts of the first 8 primes square rooted.

# 5) Initialize round constants K. 64 K constants. K values = First 32 Bits of the fractional parts of the first 64 primes cube rooted.

# 6) Chunk loop in 512 bit chunks that calculates the H values.

# 7) Create message Schedule (W)
# Create a new list that groups the 512 bit long value into 32 bit elements. Add 48 more 32 BIT 0 elements. len(Array) = 64
# Modify the indexes from 16 - 63 so using a special algorithm.
# This step leaves us with 64 WORDS in our message schedule {W}

# 8) Compression:
# Use hard coded variables, a, b, c, d, e, f, g & h. set them to h0 - h7
# Run the compression algorithm

# 9) Concatenate H0, H7. Finishes with final hash.

import random
import math
from sympy import mod_inverse


# ENCRYPTION FUNCTIONS#

class RSAEncryption:
    def __init__(self):
        pass

    # Calculating a list of Primes available for the user.
    def CalculatePrimesAvailable(self, max=100):  # Inverse fermat's little theorem
        Primes = []
        for i in range (1 ,max):
            if self.FermatsLittleTheorem(i, max - 1):
                Primes.append(i)
                # print (Primes) # Print primes with no check for Fermat PseudoPrimes.
        for Number in Primes:
            if self.CheckForFermatPseudoPrimes(Number):
                Primes.remove(Number)
        return Primes

    # Using Fermat's Little Theorem to test if a number is possibly a PRIME
    def FermatsLittleTheorem(self, i, max):
        a = random.randint(1, max)
        if (a ** (i - 1)) % i == 1:
            return True
        else:
            return False

    # Checking to see if the number found by Fermat's little theorem is a Fermat PseudoPrime.
    def CheckForFermatPseudoPrimes(self, n):
        for i in range(2, int(math.sqrt(n)) + 1, 1):
            if (n % i == 0):
                return True
        return False

    # Function that calculates the modulus(n) for the PUBLIC KEY
    def CalculateModulus(self, p, q):
        n = p * q
        return n

    # Carmichael totient function
    def Carmichael_totient_function(self, p, q):
        # λ(p * q) = lcm(p − 1, q − 1)
        LambdaPQ = self.LowestCommonMultiple( p -1, q- 1)
        return LambdaPQ


    # Works out LCM
    def LowestCommonMultiple(self, Num1, Num2):
        return abs(Num1 * Num2) // math.gcd(Num1, Num2)


    # Extended Euclidean Algorithm that calculates the inverse modulus
    def Extended_Euclidean_Algorithm(self, a, LambdaPQ):
        try:
            return pow(a, -1, LambdaPQ)
        except:
            return mod_inverse(a, LambdaPQ)

        # Function that allows user to enter values for different variables.


    def EnterUserInput(self, Letter="p", LambdaPQ=None):
        if Letter != "e" and Letter != "m":
            return int(input(f"Enter a prime from the list as your first PRIME value ({Letter}): "))
        elif Letter == "m":
            return input(f"Enter a secret Message: ")
        else:
            return int(input(f"Enter a number between 1 and {LambdaPQ}: "))

        # Function that Splits the sender's message into a list of characters.


    def SplitMessage(self, Message):
        return [char for char in Message]


    # Function that joins the list of characters
    def RejoinMessage(self, Message):
        return Message.join()


    # Convert from ASCII <=> text
    def ASCIIConversion(self, m, Convert=True):
        if Convert:
            for i in range(len(m)):
                m[i] = ord(m[i])
            return m
        else:
            return chr(m)

    # Calculates the C value for the Public Key.
    def CalculateCvalue(self, m, e, n):
        return (m ** e) % n

    # checks to see if there is a common factor > 1 between a and b.
    def CheckForCommonFactor(self, e, LambdaPQ):
        while LambdaPQ != 0:
            GCD = LambdaPQ
            LambdaPQ = e % LambdaPQ
            e = GCD
        return GCD

# HASHING ALGORITHM FUNCTIONS#

class SHAFunctions:
    def __init__(self, m):
        self.BWO = BitwiseOperations()
        self.Message = self.ConvertASCIIToBinary(self.ConvertMessageToASCII(m))
        self.MessageLength = len(self.Message)
        self.KV = self.CreateKValues()
        self.HV = self.CreateHValues()
        self.PaddedMessage = self.CreatePadding(self.Message)
        self.PaddedMessage = self.ProcessMessageBlocks(self.PaddedMessage)

        for i in range(0, len(self.PaddedMessage)):
            self.MessageSchedule = self.ModifyZeroIndexes(self.CreateMessageSchedule(self.PaddedMessage[i]))
            self.StageRegisters = self.CreateStageRegisters()
            self.HV = self.MessageCompression(self.StageRegisters, self.KV, self.HV, self.MessageSchedule)

        self.HashValue = self.MessageDigest(self.HV)
        print("Message Hash Value: ", self.HashValue)

    def MessageEntry(self):
        return (str(input("Enter the message you would like to hash: ")))

    def ConvertMessageToASCII(self, Message, MessageCharacterList=[]):
        for character in Message:
            MessageCharacterList.append(ord(character))
        return MessageCharacterList

    def ConvertASCIIToBinary(self, ASCIIMessage, BinaryNumberList=[]):
        for ASCIINumber in ASCIIMessage:
            BinaryNumberList.append(bin(ASCIINumber)[2:].zfill(8))
        BinaryNumberList = "".join(map(str, BinaryNumberList))
        return BinaryNumberList

    def CreatePadding(self, BinaryMessage):
        BigEndianNumber = self.BigEndianNumber(self.MessageLength)
        BinaryMessage += "1"
        while len(BinaryMessage) % 512 != 448:
            BinaryMessage += "0"
        return BinaryMessage + BigEndianNumber

    def BigEndianNumber(self, Length):
        return str(bin(Length)[2:].zfill(64))

    def ProcessMessageBlocks(self, Message, Increment=512):
        Blocks = [Message[i: i + Increment] for i in range(0, len(Message), Increment)]
        return Blocks

    def CreateMessageSchedule(self, PaddedMessage, Increment=32):
        W = [PaddedMessage[i: i + Increment] for i in range(0, len(PaddedMessage), Increment)]
        for i in range(0, 48):
            W.append("0" * 32)
        return W

    def ModifyZeroIndexes(self, MessageSchedule):
        for i in range(16, 64):
            # σ0:
            s0 = self.σn(i-15, 7, 18, 3, MessageSchedule)
            # σ1:
            s1 = self.σn(i-2, 17, 19, 10, MessageSchedule)
            MessageSchedule[i] = self.BWO.BinaryAddition(self.BWO.BinaryAddition(self.BWO.BinaryAddition(MessageSchedule[i-16], s0), MessageSchedule[i-7]), s1)
        return MessageSchedule

    def σn(self, IndexValue, Rot1L, Rot2L, ShiftL, MessageSchedule):
        Rot1 = self.BWO.BinaryRightRotation(MessageSchedule[IndexValue], Rot1L)
        Rot2 = self.BWO.BinaryRightRotation(MessageSchedule[IndexValue], Rot2L)
        Shift = self.BWO.BinaryRightShift(MessageSchedule[IndexValue], ShiftL)
        return self.BWO.BinaryXOR(self.BWO.BinaryXOR(Rot1, Rot2), Shift)

    def Σn(self, Rot1L, Rot2L, Rot3L, BinaryValue):
        Rot1 = self.BWO.BinaryRightRotation(BinaryValue, Rot1L)
        Rot2 = self.BWO.BinaryRightRotation(BinaryValue, Rot2L)
        Rot3 = self.BWO.BinaryRightRotation(BinaryValue, Rot3L)
        return self.BWO.BinaryXOR(self.BWO.BinaryXOR(Rot1, Rot2), Rot3)

    def CreateKValues(self):    # K values = first 32 bits of first 64 CUBEROOT Primes decimal parts
        return [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    def CreateHValues(self):    # H values = first 32 bits of first 64 SQRT Primes decimal parts
        return [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    def CreateStageRegisters(self, StageRegisters=[]):
        StageRegisters.clear()
        for i in range(len(self.HV)):
            StageRegisters.append(bin(self.HV[i])[2:].zfill(32))
        return StageRegisters

    def MessageCompression(self, StageRegisters, KV, HV, MessageSchedule):
        for i in range (0, 64):
            Σ0 = self.Σn(6, 11, 25, StageRegisters[4])
            ChoiceEFG = self.BWO.BinaryChoice(StageRegisters[4], StageRegisters[5], StageRegisters[6])
            h = StageRegisters[7]
            KVi = bin(KV[i])[2:].zfill(32)
            Wi = MessageSchedule[i]
            T1 = self.BWO.BinaryAddition(self.BWO.BinaryAddition(self.BWO.BinaryAddition(self.BWO.BinaryAddition(Σ0, ChoiceEFG), h), KVi), Wi)
            Σ1 = self.Σn(2, 13, 22, StageRegisters[0])
            MajorityABC = self.BWO.BinaryMajority(StageRegisters[0], StageRegisters[1], StageRegisters[2])
            T2 = self.BWO.BinaryAddition(Σ1, MajorityABC)
            StageRegisters = self.CompressStageRegisters(StageRegisters, T1, T2)

        for i in range (0, len(StageRegisters)):
            HV[i] = int(self.BWO.BinaryAddition(bin(self.HV[i])[2:].zfill(32), StageRegisters[i]), 2)

        return HV

    def CompressStageRegisters(self, StageResisters, T1, T2):
        CompressedRej = [0]
        for i in range(0, len(StageResisters)-1):
            CompressedRej.append(StageResisters[i])
        CompressedRej[0] = self.BWO.BinaryAddition(T1, T2)
        CompressedRej[4] = self.BWO.BinaryAddition(CompressedRej[4], T1)
        return CompressedRej

    def MessageDigest(self, CompressedHashList):
        FinalHashValue = ""
        for i in range (0, len(CompressedHashList)):
            FinalHashValue += str(hex(CompressedHashList[i]))[2:]
        return FinalHashValue

class BitwiseOperations:
    def __init__(self):
        pass

    def BinaryRightShift(self, BinaryNumber, Length):
        return bin(int(BinaryNumber, 2) >> Length)[2:].zfill(32)

    def BinaryRightRotation(self, BinaryNumber, Length):
        BitsToAdd = ""
        for i in range(0, Length):
            EndBit = BinaryNumber[len(BinaryNumber) - 1 - i]
            BitsToAdd += EndBit
        BitsToAdd = BitsToAdd[::-1]
        return BitsToAdd + BinaryNumber[0:len(BinaryNumber) - Length]

    def BinaryXOR(self, BN1, BN2):
        ExclusiveOrFunction = int(BN1, 2) ^ int(BN2, 2)
        return bin(ExclusiveOrFunction)[2:].zfill(32)

    def BinaryNOT(self, BN1):
        b_string = str(BN1)
        ib_string = ""
        for bit in b_string:
            if bit == "1":
                ib_string += "0"
            else:
                ib_string += "1"
        return bin(int(ib_string, 2))[2:].zfill(32)

    def BinaryAND(self, BN1, BN2):
        return bin(int(BN1, 2) & int(BN2, 2))[2:].zfill(32)

    def BinaryAddition(self, BN1, BN2): # Using 32 Bit binary addition
        Added = int(BN1, 2) + int(BN2, 2)
        if Added >= 2 ** 32:
            Added = Added % 2 ** 32
        Added = bin(Added)[2:].zfill(32)
        return Added

    def BinaryMajority(self, a, b, c):
        return self.BinaryXOR(self.BinaryXOR(self.BinaryAND(a, c), self.BinaryAND(a, b)), self.BinaryAND(b, c))

    def BinaryChoice(self, e, f, g):
        return self.BinaryXOR(self.BinaryAND(e, f), self.BinaryAND(self.BinaryNOT(e), g))


# MAIN #

def Main():
    RSA = RSAEncryption()
    # Calculate prime numbers.
    PN = RSA.CalculatePrimesAvailable(max=300)
    # Returns Primes to the console.
    print(f"List of Primes: {PN}")
    # Allows for the user to enter a P value and Q value (2 primes for trapdoor function).
    p = RSA.EnterUserInput()
    q = RSA.EnterUserInput(Letter="q")
    # Calculates the modulus (n) that will be used in the encryption.
    n = RSA.CalculateModulus(p, q)
    # Uses the Carmichael totient function to calculate λ(n).
    LambdaPQ = RSA.Carmichael_totient_function(p, q)
    # User can enter an E value that is used in the Public key.
    e = RSA.EnterUserInput(Letter="e", LambdaPQ=LambdaPQ)
    # Checks to see if the value given as 'e' and λ(n) have a COMMON FACTOR.
    HCF = RSA.CheckForCommonFactor(e, LambdaPQ)
    # Allows user to make secret message.
    Input = RSA.EnterUserInput(Letter="m")
    m = RSA.ASCIIConversion(RSA.SplitMessage(Input), Convert=True)
    c = []
    try:
        # D value calculated.
        d = RSA.Extended_Euclidean_Algorithm(e, LambdaPQ)
        for i in range(len(m)):
            # C value calculated.
            c.append(RSA.CalculateCvalue(m[i], e, n))

        CipheredMessage = ''.join(map(str, c))
        print(f"Ciphered Message: {(''.join(map(str, c)))}")
        # Producing the Hash value for the message
        MessageHash = SHAFunctions(Input)
        # returning the original message after being encoded.
        FinalStr = ""
        for i in range(len(m)):
            FinalStr += RSA.ASCIIConversion(int((c[i] ** d) % n), Convert=False)
        print(f"Final String decrypted: {FinalStr}")
    except:
        print(f"{LambdaPQ} and {e} have a COMMON FACTOR which is > 1 [{HCF}]")
        Main()


if __name__ == "__main__":
    Main()