using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;

namespace wan24.TSAClient
{
    /// <summary>
    /// High level TSA helper (BouncyCastle wrapper)
    /// </summary>
    public static class TSA
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
        /// Default SHA hash algorithm name
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

        /// <summary>
        /// BouncyCastle PCL version
        /// </summary>
        private static string _BC_VERSION = null;

        /// <summary>
        /// Get the TSA Client library version
        /// </summary>
        public static string VERSION => Properties.Resources.VERSION;

        /// <summary>
        /// BouncyCastle PCL version
        /// </summary>
        public static string BC_VERSION =>
            _BC_VERSION ?? (_BC_VERSION = typeof(TimeStampToken).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion);

        /// <summary>
        /// Create a hash from a file
        /// </summary>
        /// <param name="fileName">Filename</param>
        /// <param name="algorithm">SHA hash algorithm name</param>
        /// <returns>Hash</returns>
        public static byte[] CreateHash(string fileName, string algorithm = DEFAULT_HASH)
        {
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            using (Stream fs = File.OpenRead(fileName))
                switch (algorithm.ToLower())
                {
                    case HASH_SHA1:
                        using (SHA1 sha = SHA1.Create()) return sha.ComputeHash(fs);
                    case HASH_SHA256:
                        using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(fs);
                    case HASH_SHA384:
                        using (SHA384 sha = SHA384.Create()) return sha.ComputeHash(fs);
                    case HASH_SHA512:
                        using (SHA512 sha = SHA512.Create()) return sha.ComputeHash(fs);
                    default:
                        throw new ArgumentException("Unknown algorithm", nameof(algorithm));
                }
        }

        /// <summary>
        /// Create a hash from bytes
        /// </summary>
        /// <param name="data">Bytes</param>
        /// <param name="algorithm">SHA hash algorithm name</param>
        /// <returns>Hash</returns>
        public static byte[] CreateHash(byte[] data, string algorithm = DEFAULT_HASH)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            switch (algorithm.ToLower())
            {
                case HASH_SHA1:
                    using (SHA1 sha = SHA1.Create()) return sha.ComputeHash(data);
                case HASH_SHA256:
                    using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(data);
                case HASH_SHA384:
                    using (SHA384 sha = SHA384.Create()) return sha.ComputeHash(data);
                case HASH_SHA512:
                    using (SHA512 sha = SHA512.Create()) return sha.ComputeHash(data);
                default:
                    throw new ArgumentException("Unknown algorithm", nameof(algorithm));
            }
        }

        /// <summary>
        /// Create a TSQ
        /// </summary>
        /// <param name="hash">Hash</param>
        /// <param name="outFile">Target filename</param>
        /// <param name="includeCert">Include certificates?</param>
        /// <returns>TSQ</returns>
        public static byte[] CreateRequest(byte[] hash, string outFile = null, bool includeCert = true)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            string algorithm;
            switch (hash.Length)
            {
                case HASH_SHA1_LEN:
                    algorithm = TspAlgorithms.Sha1;
                    break;
                case HASH_SHA256_LEN:
                    algorithm = TspAlgorithms.Sha256;
                    break;
                case HASH_SHA384_LEN:
                    algorithm = TspAlgorithms.Sha384;
                    break;
                case HASH_SHA512_LEN:
                    algorithm = TspAlgorithms.Sha512;
                    break;
                default:
                    throw new ArgumentException("Unsupported hash length", nameof(hash));
            }
            TimeStampRequestGenerator tsqg = new TimeStampRequestGenerator();
            tsqg.SetCertReq(includeCert);
            TimeStampRequest tsq = tsqg.Generate(algorithm, hash);
            byte[] data = tsq.GetEncoded();
            if (outFile != null)
            {
                if (File.Exists(outFile)) File.Delete(outFile);
                using (Stream fs = File.OpenWrite(outFile))
                    fs.Write(data, 0, data.Length);
            }
            return data;
        }

        /// <summary>
        /// Send a request (receive a TSR)
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <param name="uri">TSA URI</param>
        /// <param name="outFile">Target filename</param>
        /// <returns>TSR</returns>
        public static byte[] SendRequest(string tsqFile, string uri, string outFile = null)
        {
            if (tsqFile == null) throw new ArgumentNullException(nameof(tsqFile));
            if (uri == null) throw new ArgumentNullException(nameof(uri));
            return SendRequest(File.ReadAllBytes(tsqFile), uri, outFile);
        }

        /// <summary>
        /// Send a request (receive a TSR)
        /// </summary>
        /// <param name="tsq">TSQ</param>
        /// <param name="uri">TSA URI (or <see langword="null"/>, if <c>req</c> is given)</param>
        /// <param name="outFile">Target filename</param>
        /// <param name="req">Request to reuse</param>
        /// <returns>TSR</returns>
        public static byte[] SendRequest(byte[] tsq, string uri, string outFile = null, HttpWebRequest req = null)
        {
            if (tsq == null) throw new ArgumentNullException(nameof(tsq));
            if (req == null)
            {
                if (uri == null) throw new ArgumentNullException(nameof(uri));
                req = (HttpWebRequest)WebRequest.Create(uri);
            }
            req.Method = "POST";
            req.ContentType = "application/timestamp-query";
            req.ContentLength = tsq.Length;
            if (outFile != null && File.Exists(outFile)) File.Delete(outFile);
            using (Stream rs = req.GetRequestStream())
                rs.Write(tsq, 0, tsq.Length);
            using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
            using (Stream rs = new BufferedStream(res.GetResponseStream()))
            using (MemoryStream ms = new MemoryStream())
            using (Stream fs = outFile == null ? null : File.OpenWrite(outFile))
            {
                rs.CopyTo(ms);
                if (fs != null)
                {
                    ms.Position = 0;
                    ms.CopyTo(fs);
                }
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Validate a TSR using the TSQ
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <param name="tsrFile">TSR filename</param>
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
        public static void ValidateSourceTsr(string tsrFile, string fileName)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            TimeStampResponse tsr = GetResponse(tsrFile);
            if (tsr.Status != 0) throw new InvalidDataException($"TSR status is #{tsr.Status}");
            ValidateSourceToken(tsr.TimeStampToken, CreateHash(fileName, GetHashAlgorithm(tsr.TimeStampToken.TimeStampInfo.GetMessageImprintDigest().Length)));
        }

        /// <summary>
        /// Get the hash algorithm from a hash length
        /// </summary>
        /// <param name="len">Hash length</param>
        /// <returns>Algorithm</returns>
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

        /// <summary>
        /// Validate a TSR using the source hash
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <param name="hash">Source hash</param>
        public static void ValidateSourceTsr(string tsrFile, byte[] hash)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(GetResponse(tsrFile).TimeStampToken, hash);
        }

        /// <summary>
        /// Validate a TSR using the source hash
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <param name="hash">Source hash</param>
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
        public static void ValidateSourceToken(string tokenFile, string fileName)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            TimeStampToken token = GetToken(tokenFile);
            ValidateSourceToken(token, CreateHash(fileName, GetHashAlgorithm(token.TimeStampInfo.GetMessageImprintDigest().Length)));
        }

        /// <summary>
        /// Validate a timestamp token using the source hash
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <param name="hash">Source hash</param>
        public static void ValidateSourceToken(string tokenFile, byte[] hash)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(File.ReadAllBytes(tokenFile), hash);
        }

        /// <summary>
        /// Validate a timestamp token using the source hash
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <param name="hash">Source hash</param>
        public static void ValidateSourceToken(byte[] tokenData, byte[] hash)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            ValidateSourceToken(GetToken(tokenData), hash);
        }

        /// <summary>
        /// Validate a timestamp token using the source hash
        /// </summary>
        /// <param name="token">Timestamp token</param>
        /// <param name="hash">Source hash</param>
        internal static void ValidateSourceToken(TimeStampToken token, byte[] hash)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (!token.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(hash))
                throw new InvalidDataException("Source hash doesn't match the TSR digest");
        }

        /// <summary>
        /// Extract the timestamp token from a TSR
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <param name="outFile">Target filename</param>
        /// <returns>Token</returns>
        public static byte[] ExtractToken(string tsrFile, string outFile = null)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            return ExtractToken(File.ReadAllBytes(tsrFile), outFile);
        }

        /// <summary>
        /// Extract the timestamp token from a TSR
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <param name="outFile">Target filename</param>
        /// <returns>Token</returns>
        public static byte[] ExtractToken(byte[] tsrData, string outFile = null)
        {
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            TimeStampResponse tsr = GetResponse(tsrData);
            byte[] res = tsr.TimeStampToken.GetEncoded();
            if (outFile != null)
            {
                if (File.Exists(outFile)) File.Delete(outFile);
                File.WriteAllBytes(outFile, res);
            }
            return res;
        }

        /// <summary>
        /// Validate a timestamp token using a X509 certificate
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <param name="certFile">X509 certificate filename</param>
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
        public static void ValidateToken(byte[] tokenData, string certFile)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            if (certFile == null) throw new ArgumentNullException(nameof(certFile));
            GetToken(tokenData).Validate(new X509Certificate(File.ReadAllBytes(certFile)));
        }

        /// <summary>
        /// Get TSQ information
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <returns>Information</returns>
        public static IEnumerable<string> RequestInfo(string tsqFile)
        {
            if (tsqFile == null) throw new ArgumentNullException(nameof(tsqFile));
            foreach (string info in RequestInfo(File.ReadAllBytes(tsqFile))) yield return info;
        }

        /// <summary>
        /// Get TSQ information
        /// </summary>
        /// <param name="tsqData">TSQ</param>
        /// <returns>Information</returns>
        public static IEnumerable<string> RequestInfo(byte[] tsqData)
        {
            if (tsqData == null) throw new ArgumentNullException(nameof(tsqData));
            TimeStampRequest tsq = GetRequest(tsqData);
            yield return $"TSQ version: {tsq.Version}";
            yield return $"TSQ digest algorithm OID: {tsq.MessageImprintAlgOid}";
            yield return $"TSQ digest: {(tsq.GetMessageImprintDigest() == null ? string.Empty : BitConverter.ToString(tsq.GetMessageImprintDigest()).Replace("-", string.Empty))}";
            yield return $"TSQ policy: {tsq.ReqPolicy}";
            yield return $"TSQ certificates: {tsq.CertReq}";
            yield return $"TSQ nonce: {(tsq.Nonce == null ? string.Empty : BitConverter.ToString(tsq.Nonce.ToByteArray()).Replace("-", string.Empty))}";
            yield return $"TSQ has extensions: {tsq.HasExtensions}";
            if (tsq.HasExtensions)
                foreach (var oid in tsq.GetExtensionOids())
                    yield return $"TSQ extension OID {oid}: {tsq.GetExtensionValue((DerObjectIdentifier)oid)}";
        }

        /// <summary>
        /// Get TSR information
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <returns>Information</returns>
        public static IEnumerable<string> ResponseInfo(string tsrFile)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            foreach (string info in ResponseInfo(File.ReadAllBytes(tsrFile))) yield return info;
        }

        /// <summary>
        /// Get TSR information
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <returns>Information</returns>
        public static IEnumerable<string> ResponseInfo(byte[] tsrData)
        {
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            TimeStampResponse tsr = GetResponse(tsrData);
            yield return $"TSR status: {tsr.Status}";
            if (tsr.TimeStampToken != null) foreach (string info in TokenInfo(tsr.TimeStampToken)) yield return info;
        }

        /// <summary>
        /// Get timestamp token information
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <returns>Information</returns>
        public static IEnumerable<string> TokenInfo(string tokenFile)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            foreach (string info in RequestInfo(File.ReadAllBytes(tokenFile))) yield return info;
        }

        /// <summary>
        /// Get timestamp token information
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <returns>Information</returns>
        public static IEnumerable<string> TokenInfo(byte[] tokenData)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            foreach (string info in TokenInfo(GetToken(tokenData))) yield return info;
        }

        /// <summary>
        /// Get timestamp token information
        /// </summary>
        /// <param name="token">Timestamp token</param>
        /// <returns>Information</returns>
        internal static IEnumerable<string> TokenInfo(TimeStampToken token)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            yield return $"Signer serial: {token.SignerID.SerialNumber}";
            yield return $"Issuer: {token.SignerID.Issuer}";
            if (token.TimeStampInfo != null)
            {
                yield return $"TSA: {token.TimeStampInfo.Tsa?.Name}";
                yield return $"Timestamp version: {token.TimeStampInfo.TstInfo?.Version}";
                yield return $"Timestamp serial: {token.TimeStampInfo.SerialNumber}";
                yield return $"Timestamp policy: {token.TimeStampInfo.Policy}";
                yield return $"Timestamp gen. time: {(token.TimeStampInfo.GenTime == null ? string.Empty : token.TimeStampInfo.GenTime.ToLocalTime().ToString("O"))}";
                yield return $"Timestamp gen. time accurancy: {(token.TimeStampInfo.GenTimeAccuracy == null ? string.Empty : $"{token.TimeStampInfo.GenTimeAccuracy.Seconds}-{token.TimeStampInfo.GenTimeAccuracy.Millis}-{token.TimeStampInfo.GenTimeAccuracy.Micros}")}";
                yield return $"Timestamp nonce: {(token.TimeStampInfo.Nonce == null ? string.Empty : BitConverter.ToString(token.TimeStampInfo.Nonce.ToByteArray()).Replace("-", string.Empty))}";
                yield return $"Timestamp digest algorithm OID: {token.TimeStampInfo.MessageImprintAlgOid}";
                yield return $"Timestamp digest: {BitConverter.ToString(token.TimeStampInfo.GetMessageImprintDigest()).Replace("-", string.Empty)}";
            }
        }

        /// <summary>
        /// Get a TSQ
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <returns>TSQ</returns>
        public static TimeStampRequest GetRequest(string tsqFile)
        {
            if (tsqFile == null) throw new ArgumentNullException(nameof(tsqFile));
            return new TimeStampRequest(File.ReadAllBytes(tsqFile));
        }

        /// <summary>
        /// Get a TSR
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <returns>TSR</returns>
        public static TimeStampResponse GetResponse(string tsrFile)
        {
            if (tsrFile == null) throw new ArgumentNullException(nameof(tsrFile));
            return new TimeStampResponse(File.ReadAllBytes(tsrFile));
        }

        /// <summary>
        /// Get a timestamp token
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <returns>Timestamp token</returns>
        public static TimeStampToken GetToken(string tokenFile)
        {
            if (tokenFile == null) throw new ArgumentNullException(nameof(tokenFile));
            return new TimeStampToken(new CmsSignedData(File.ReadAllBytes(tokenFile)));
        }

        /// <summary>
        /// Get a TSQ
        /// </summary>
        /// <param name="tsqData">TSQ</param>
        /// <returns>TSQ</returns>
        public static TimeStampRequest GetRequest(byte[] tsqData)
        {
            if (tsqData == null) throw new ArgumentNullException(nameof(tsqData));
            return new TimeStampRequest(tsqData);
        }

        /// <summary>
        /// Get a TSR
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <returns>TSR</returns>
        public static TimeStampResponse GetResponse(byte[] tsrData)
        {
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            return new TimeStampResponse(tsrData);
        }

        /// <summary>
        /// Get a timestamp token
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <returns>Timestamp token</returns>
        public static TimeStampToken GetToken(byte[] tokenData)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            return new TimeStampToken(new CmsSignedData(tokenData));
        }

        /// <summary>
        /// Get a TSQ
        /// </summary>
        /// <param name="tsqData">TSQ</param>
        /// <returns>TSQ</returns>
        public static TimeStampRequest GetRequest(Stream tsqData)
        {
            if (tsqData == null) throw new ArgumentNullException(nameof(tsqData));
            return new TimeStampRequest(tsqData);
        }

        /// <summary>
        /// Get a TSR
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <returns>TSR</returns>
        public static TimeStampResponse GetResponse(Stream tsrData)
        {
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            return new TimeStampResponse(tsrData);
        }

        /// <summary>
        /// Get a timestamp token
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <returns>Timestamp token</returns>
        public static TimeStampToken GetToken(Stream tokenData)
        {
            if (tokenData == null) throw new ArgumentNullException(nameof(tokenData));
            return new TimeStampToken(new CmsSignedData(tokenData));
        }
    }
}