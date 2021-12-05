using Org.BouncyCastle.Tsp;
using System;
using System.IO;

namespace wan24.TSAClient
{
    // Timestamp token methods
    public static partial class TSA
    {
        /// <summary>
        /// Extract the timestamp token from a TSR
        /// </summary>
        /// <param name="tsrFile">TSR filename</param>
        /// <param name="outFile">Target filename</param>
        /// <returns>Timestamp token</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
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
        /// <returns>Timestamp token</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static byte[] ExtractToken(byte[] tsrData, string outFile = null)
        {
            if (tsrData == null) throw new ArgumentNullException(nameof(tsrData));
            TimeStampResponse tsr = GetResponse(tsrData);
            byte[] res = tsr.TimeStampToken.GetEncoded();
            if (outFile == null) return res;
            if (File.Exists(outFile)) File.Delete(outFile);
            File.WriteAllBytes(outFile, res);
            return res;
        }
    }
}
