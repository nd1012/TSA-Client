using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Linq;

namespace wan24.TSAClient
{
    // TSQ/TSR/Timestamp token validation methods
    public static partial class TSA
    {
        /// <summary>
        /// Validate a TSR using the TSQ
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <param name="tsrFile">TSR filename</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateResponse(string tsqFile, string tsrFile)
        {
            if (tsqFile == null) throw new ArgumentNullException(nameof(tsqFile));
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            ValidateResponse(File.ReadAllBytes(tsqFile), File.ReadAllBytes(tsrFile));
        }

        /// <summary>
        /// Validate a TSR using the TSQ
        /// </summary>
        /// <param name="tsqData">TSQ</param>
        /// <param name="tsrData">TSR</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        /// <exception cref="InvalidDataException">TSA returned an error status code</exception>
        public static void ValidateResponse(byte[] tsqData, byte[] tsrData)
        {
            if (tsqData == null) throw new ArgumentNullException(nameof(tsqData));
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            TimeStampResponse tsr = GetResponse(tsrData);
            if (tsr.Status != 0) throw new InvalidDataException($"TSR status is #{tsr.Status}");
            tsr.Validate(GetRequest(tsqData));
        }

        /// <summary>
        /// Validate a TSR using the source file
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <param name="fileName">Source filename</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        /// <exception cref="InvalidDataException">TSA returned an error status code</exception>
        public static void ValidateSourceTsr(string tsrFile, string fileName)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            TimeStampResponse tsr = GetResponse(tsrFile);
            if (tsr.Status != 0) throw new InvalidDataException($"TSR status is #{tsr.Status}");
            ValidateSourceToken(tsr.TimeStampToken, CreateHash(fileName, GetHashAlgorithm(tsr.TimeStampToken.TimeStampInfo.GetMessageImprintDigest().Length)));
        }

        /// <summary>
        /// Validate a TSR using the source SHA hash
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <param name="hash">Source SHA hash</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateSourceTsr(string tsrFile, byte[] hash)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(GetResponse(tsrFile).TimeStampToken, hash);
        }

        /// <summary>
        /// Validate a TSR using the source SHA hash
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <param name="hash">Source SHA hash</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateSourceTsr(byte[] tsrData, byte[] hash)
        {
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(GetResponse(tsrData).TimeStampToken, hash);
        }

        /// <summary>
        /// Validate a timestamp token using the source file
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <param name="fileName">Source filename</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateSourceToken(string tokenFile, string fileName)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            TimeStampToken token = GetToken(tokenFile);
            ValidateSourceToken(token, CreateHash(fileName, GetHashAlgorithm(token.TimeStampInfo.GetMessageImprintDigest().Length)));
        }

        /// <summary>
        /// Validate a timestamp token using the source SHA hash
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <param name="hash">Source SHA hash</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateSourceToken(string tokenFile, byte[] hash)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(File.ReadAllBytes(tokenFile), hash);
        }

        /// <summary>
        /// Validate a timestamp token using the source SHA hash
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <param name="hash">Source SHA hash</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateSourceToken(byte[] tokenData, byte[] hash)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(GetToken(tokenData), hash);
        }

        /// <summary>
        /// Validate a timestamp token using the source SHA hash
        /// </summary>
        /// <param name="token">Timestamp token</param>
        /// <param name="hash">Source SHA hash</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        /// <exception cref="InvalidDataException">Source SHA hash doesn't match the TSR digest</exception>
        internal static void ValidateSourceToken(TimeStampToken token, byte[] hash)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (!token.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(hash))
                throw new InvalidDataException("Source hash doesn't match the TSR digest");
        }

        /// <summary>
        /// Validate a timestamp token using a X509 certificate
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <param name="certFile">X509 certificate filename</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateToken(string tokenFile, string certFile)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            if (certFile == null) throw new ArgumentNullException(nameof(certFile));
            ValidateToken(File.ReadAllBytes(tokenFile), certFile);
        }

        /// <summary>
        /// Validate a timestamp token using a X509 certificate
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <param name="certFile">X509 certificate filename</param>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static void ValidateToken(byte[] tokenData, string certFile)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            if (certFile == null) throw new ArgumentNullException(nameof(certFile));
            GetToken(tokenData).Validate(new X509Certificate(File.ReadAllBytes(certFile)));
        }
    }
}
