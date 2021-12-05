using System;
using System.IO;
using System.Security.Cryptography;

namespace wan24.TSAClient
{
    // Hash methods
    public static partial class TSA
    {
        /// <summary>
        /// Create a SHA hash from a file
        /// </summary>
        /// <param name="fileName">Filename</param>
        /// <param name="algorithm">SHA hash algorithm name</param>
        /// <returns>Hash</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        /// <exception cref="ArgumentException">Unknown SHA hash algorithm name</exception>
        public static byte[] CreateHash(string fileName, string algorithm = DEFAULT_HASH)
        {
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            using (Stream fs = File.OpenRead(fileName))
                switch (algorithm.ToLower())
                {
                    case HASH_SHA1: using (SHA1 sha = SHA1.Create()) return sha.ComputeHash(fs);
                    case HASH_SHA256: using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(fs);
                    case HASH_SHA384: using (SHA384 sha = SHA384.Create()) return sha.ComputeHash(fs);
                    case HASH_SHA512: using (SHA512 sha = SHA512.Create()) return sha.ComputeHash(fs);
                    default: throw new ArgumentException("Unknown algorithm", nameof(algorithm));
                }
        }

        /// <summary>
        /// Create a SHA hash from bytes
        /// </summary>
        /// <param name="data">Bytes</param>
        /// <param name="algorithm">SHA hash algorithm name</param>
        /// <returns>Hash</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        /// <exception cref="ArgumentException">Unknown SHA hash algorithm name</exception>
        public static byte[] CreateHash(byte[] data, string algorithm = DEFAULT_HASH)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            switch (algorithm.ToLower())
            {
                case HASH_SHA1: using (SHA1 sha = SHA1.Create()) return sha.ComputeHash(data);
                case HASH_SHA256: using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(data);
                case HASH_SHA384: using (SHA384 sha = SHA384.Create()) return sha.ComputeHash(data);
                case HASH_SHA512: using (SHA512 sha = SHA512.Create()) return sha.ComputeHash(data);
                default: throw new ArgumentException("Unknown algorithm", nameof(algorithm));
            }
        }

        /// <summary>
        /// Get the SHA hash algorithm name from a SHA hash length
        /// </summary>
        /// <param name="len">SHA hash length</param>
        /// <returns>SHA algorithm name</returns>
        /// <exception cref="ArgumentException">Unsupported SHA hash length</exception>
        internal static string GetHashAlgorithm(int len)
        {
            switch (len)
            {
                case HASH_SHA1_LEN: return HASH_SHA1;
                case HASH_SHA256_LEN: return HASH_SHA256;
                case HASH_SHA384_LEN: return HASH_SHA384;
                case HASH_SHA512_LEN: return HASH_SHA512;
                default: throw new ArgumentException("Unsupported hash length", nameof(len));
            }
        }
    }
}
