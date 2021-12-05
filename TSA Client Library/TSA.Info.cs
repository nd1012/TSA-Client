using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Tsp;
using System;
using System.Collections.Generic;
using System.IO;

namespace wan24.TSAClient
{
    // Information methods
    public static partial class TSA
    {
        /// <summary>
        /// Get TSQ information
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <returns>Information</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
    }
}
