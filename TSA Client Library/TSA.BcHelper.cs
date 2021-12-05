using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;

namespace wan24.TSAClient
{
    // BouncyCastle-PCR helper methods
    public static partial class TSA
    {
        /// <summary>
        /// Get a TSQ
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <returns>TSQ</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampRequest GetRequest(string tsqFile)
            => new TimeStampRequest(File.ReadAllBytes(tsqFile ?? throw new ArgumentNullException(nameof(tsqFile))));

        /// <summary>
        /// Get a TSR
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <returns>TSR</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampResponse GetResponse(string tsrFile)
            => new TimeStampResponse(File.ReadAllBytes(tsrFile ?? throw new ArgumentNullException(nameof(tsrFile))));

        /// <summary>
        /// Get a timestamp token
        /// </summary>
        /// <param name="tokenFile">Timestamp token filename</param>
        /// <returns>Timestamp token</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampToken GetToken(string tokenFile)
            => new TimeStampToken(new CmsSignedData(File.ReadAllBytes(tokenFile ?? throw new ArgumentNullException(nameof(tokenFile)))));

        /// <summary>
        /// Get a TSQ
        /// </summary>
        /// <param name="tsqData">TSQ</param>
        /// <returns>TSQ</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampRequest GetRequest(byte[] tsqData)
            => new TimeStampRequest(tsqData ?? throw new ArgumentNullException(nameof(tsqData)));

        /// <summary>
        /// Get a TSR
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <returns>TSR</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampResponse GetResponse(byte[] tsrData)
            => new TimeStampResponse(tsrData ?? throw new ArgumentNullException(nameof(tsrData)));

        /// <summary>
        /// Get a timestamp token
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <returns>Timestamp token</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampToken GetToken(byte[] tokenData)
            => new TimeStampToken(new CmsSignedData(tokenData ?? throw new ArgumentNullException(nameof(tokenData))));

        /// <summary>
        /// Get a TSQ
        /// </summary>
        /// <param name="tsqData">TSQ</param>
        /// <returns>TSQ</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampRequest GetRequest(Stream tsqData)
            => new TimeStampRequest(tsqData ?? throw new ArgumentNullException(nameof(tsqData)));

        /// <summary>
        /// Get a TSR
        /// </summary>
        /// <param name="tsrData">TSR</param>
        /// <returns>TSR</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampResponse GetResponse(Stream tsrData)
            => new TimeStampResponse(tsrData ?? throw new ArgumentNullException(nameof(tsrData)));

        /// <summary>
        /// Get a timestamp token
        /// </summary>
        /// <param name="tokenData">Timestamp token</param>
        /// <returns>Timestamp token</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static TimeStampToken GetToken(Stream tokenData)
            => new TimeStampToken(new CmsSignedData(tokenData ?? throw new ArgumentNullException(nameof(tokenData))));
    }
}
