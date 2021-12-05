namespace wan24.TSAClient
{
    // Class constants
    public static partial class TSA
    {
        /// <summary>
        /// SHA1 hash algorithm name
        /// </summary>
        public const string HASH_SHA1 = "sha1";
        /// <summary>
        /// SHA256 hash algorithm name
        /// </summary>
        public const string HASH_SHA256 = "sha256";
        /// <summary>
        /// SHA384 hash algorithm name
        /// </summary>
        public const string HASH_SHA384 = "sha384";
        /// <summary>
        /// SHA512 hash algorithm name
        /// </summary>
        public const string HASH_SHA512 = "sha512";
        /// <summary>
        /// Default SHA hash algorithm name (SHA512)
        /// </summary>
        public const string DEFAULT_HASH = HASH_SHA512;
        /// <summary>
        /// SHA1 hash length
        /// </summary>
        public const int HASH_SHA1_LEN = 20;
        /// <summary>
        /// SHA256 hash length
        /// </summary>
        public const int HASH_SHA256_LEN = 32;
        /// <summary>
        /// SHA384 hash length
        /// </summary>
        public const int HASH_SHA384_LEN = 48;
        /// <summary>
        /// SHA512 hash length
        /// </summary>
        public const int HASH_SHA512_LEN = 64;
    }
}
