using System;
using System.Collections.Generic;

public class AESCustom
{
    private readonly byte[] SBox = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    private readonly byte[] InvSBox = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    private readonly byte[] Rcon = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };


    private byte[] PadPKCS7(byte[] input)
    {
        int paddingLength = 16 - (input.Length % 16);
        byte[] padded = new byte[input.Length + paddingLength];
        Array.Copy(input, 0, padded, 0, input.Length);
        
        for (int i = input.Length; i < padded.Length; i++)
        {
            padded[i] = (byte)paddingLength;
        }
        
        return padded;
    }

    private byte[] RemovePKCS7(byte[] input)
    {
        int paddingLength = input[input.Length - 1];
        byte[] unpadded = new byte[input.Length - paddingLength];
        Array.Copy(input, 0, unpadded, 0, unpadded.Length);
        return unpadded;
    }

    private byte[][] KeyExpansion(byte[] key)
    {
        byte[][] w = new byte[44][];
        
        for (int i = 0; i < 4; i++)
        {
            w[i] = new byte[4];
            Array.Copy(key, i * 4, w[i], 0, 4);
        }
        
        for (int i = 4; i < 44; i++)
        {
            byte[] temp = new byte[4];
            Array.Copy(w[i - 1], temp, 4);
            
            if (i % 4 == 0)
            {
                temp = SubWord(RotWord(temp));
                temp[0] ^= Rcon[i / 4 - 1];
            }
            
            w[i] = new byte[4];
            for (int j = 0; j < 4; j++)
            {
                w[i][j] = (byte)(w[i - 4][j] ^ temp[j]);
            }
        }
        
        return w;
    }

    private byte[] RotWord(byte[] word)
    {
        return new byte[] { word[1], word[2], word[3], word[0] };
    }

    private byte[] SubWord(byte[] word)
    {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            result[i] = SBox[word[i]];
        }
        return result;
    }

    private byte[] EncryptBlock(byte[] block, byte[][] roundKeys)
    {
        byte[] state = new byte[16];
        Array.Copy(block, state, 16);
        
        AddRoundKey(state, roundKeys, 0);
        
        for (int round = 1; round < 10; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, roundKeys, round);
        }
        
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, roundKeys, 10);
        
        return state;
    }

    private byte[] DecryptBlock(byte[] block, byte[][] roundKeys)
    {
        byte[] state = new byte[16];
        Array.Copy(block, state, 16);
        
        AddRoundKey(state, roundKeys, 10);
        InvShiftRows(state);
        InvSubBytes(state);
        
        for (int round = 9; round >= 1; round--)
        {
            AddRoundKey(state, roundKeys, round);
            InvMixColumns(state);
            InvShiftRows(state);
            InvSubBytes(state);
        }
        
        AddRoundKey(state, roundKeys, 0);
        
        return state;
    }

    private void SubBytes(byte[] state)
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] = SBox[state[i]];
        }
    }

    private void InvSubBytes(byte[] state)
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] = InvSBox[state[i]];
        }
    }

    private void ShiftRows(byte[] state)
    {
        byte temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        Swap(ref state[2], ref state[10]);
        Swap(ref state[6], ref state[14]);
        
        temp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = temp;
    }

    private void InvShiftRows(byte[] state)
    {
        byte temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;
        
        Swap(ref state[2], ref state[10]);
        Swap(ref state[6], ref state[14]);
        
        temp = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = state[3];
        state[3] = temp;
    }

    private void Swap(ref byte a, ref byte b)
    {
        byte temp = a;
        a = b;
        b = temp;
    }

    private void MixColumns(byte[] state)
    {
        for (int i = 0; i < 4; i++)
        {
            int offset = i * 4;
            byte s0 = state[offset];
            byte s1 = state[offset + 1];
            byte s2 = state[offset + 2];
            byte s3 = state[offset + 3];
            
            state[offset] = (byte)(GMul(0x02, s0) ^ GMul(0x03, s1) ^ s2 ^ s3);
            state[offset + 1] = (byte)(s0 ^ GMul(0x02, s1) ^ GMul(0x03, s2) ^ s3);
            state[offset + 2] = (byte)(s0 ^ s1 ^ GMul(0x02, s2) ^ GMul(0x03, s3));
            state[offset + 3] = (byte)(GMul(0x03, s0) ^ s1 ^ s2 ^ GMul(0x02, s3));
        }
    }

    private void InvMixColumns(byte[] state)
    {
        for (int i = 0; i < 4; i++)
        {
            int offset = i * 4;
            byte s0 = state[offset];
            byte s1 = state[offset + 1];
            byte s2 = state[offset + 2];
            byte s3 = state[offset + 3];
            
            state[offset] = (byte)(GMul(0x0E, s0) ^ GMul(0x0B, s1) ^ GMul(0x0D, s2) ^ GMul(0x09, s3));
            state[offset + 1] = (byte)(GMul(0x09, s0) ^ GMul(0x0E, s1) ^ GMul(0x0B, s2) ^ GMul(0x0D, s3));
            state[offset + 2] = (byte)(GMul(0x0D, s0) ^ GMul(0x09, s1) ^ GMul(0x0E, s2) ^ GMul(0x0B, s3));
            state[offset + 3] = (byte)(GMul(0x0B, s0) ^ GMul(0x0D, s1) ^ GMul(0x09, s2) ^ GMul(0x0E, s3));
        }
    }

    private byte GMul(byte a, byte b)
    {
        byte p = 0;
        byte counter;
        byte hi_bit_set;
        
        for (counter = 0; counter < 8; counter++)
        {
            if ((b & 1) != 0)
            {
                p ^= a;
            }
            
            hi_bit_set = (byte)(a & 0x80);
            a <<= 1;
            if (hi_bit_set != 0)
            {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        
        return p;
    }

    private void AddRoundKey(byte[] state, byte[][] roundKeys, int round)
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] ^= roundKeys[round * 4 + i / 4][i % 4];
        }
    }

    public byte[] EncryptECB(byte[] input, byte[] key)
    {
        byte[] paddedInput = PadPKCS7(input);
        
        byte[][] roundKeys = KeyExpansion(key);
        
        byte[] output = new byte[paddedInput.Length];
        
        for (int i = 0; i < paddedInput.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(paddedInput, i, block, 0, 16);
            
            byte[] encryptedBlock = EncryptBlock(block, roundKeys);
            Array.Copy(encryptedBlock, 0, output, i, 16);
        }
        
        return output;
    }

    public byte[] DecryptECB(byte[] input, byte[] key)
    {
        byte[][] roundKeys = KeyExpansion(key);
        
        byte[] output = new byte[input.Length];
        
        for (int i = 0; i < input.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(input, i, block, 0, 16);
            
            byte[] decryptedBlock = DecryptBlock(block, roundKeys);
            Array.Copy(decryptedBlock, 0, output, i, 16);
        }
        
        return RemovePKCS7(output);
    }

    public byte[] EncryptCBC(byte[] input, byte[] key, byte[] iv)
    {
        byte[] paddedInput = PadPKCS7(input);
        byte[][] roundKeys = KeyExpansion(key);
        
        byte[] output = new byte[paddedInput.Length];
        byte[] previousBlock = new byte[16];
        Array.Copy(iv, previousBlock, 16);

        for (int i = 0; i < paddedInput.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(paddedInput, i, block, 0, 16);
            for (int j = 0; j < 16; j++)
            {
                block[j] ^= previousBlock[j];
            }
            byte[] encryptedBlock = EncryptBlock(block, roundKeys);
            Array.Copy(encryptedBlock, 0, output, i, 16);
        
            Array.Copy(encryptedBlock, previousBlock, 16);
        }
        
        return output;
    }

    public byte[] DecryptCBC(byte[] input, byte[] key, byte[] iv)
    {
        byte[][] roundKeys = KeyExpansion(key);
        
        byte[] output = new byte[input.Length];
        byte[] previousBlock = new byte[16];
        Array.Copy(iv, previousBlock, 16);

        for (int i = 0; i < input.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(input, i, block, 0, 16);
            
            byte[] decryptedBlock = DecryptBlock(block, roundKeys);
            
            for (int j = 0; j < 16; j++)
            {
                decryptedBlock[j] ^= previousBlock[j];
            }
            
            Array.Copy(decryptedBlock, 0, output, i, 16);
            Array.Copy(block, previousBlock, 16);
        }
        return RemovePKCS7(output);
    }
}