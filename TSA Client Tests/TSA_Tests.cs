using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using wan24.TSAClient;

namespace TSA_Client_Tests
{
    [TestClass]
    public class TSA_Tests
    {
        [TestMethod]
        public void TSA_Test()
        {
            // Random data that will be timestamped
            byte[] random = new byte[100];
            Random.Shared.NextBytes(random);
            // Create the source data hash
            byte[] hash = TSA.CreateHash(random);
            Assert.IsNotNull(hash);
            Assert.IsTrue(hash.Length > 0);
            // Create a TSQ
            byte[] tsq = TSA.CreateRequest(hash);
            Assert.IsNotNull(tsq);
            Assert.IsTrue(tsq.Length > 0);
            // Request the TSR
            byte[] tsr = TSA.SendRequest(tsq, "https://freetsa.org/tsr");
            Assert.IsNotNull(tsr);
            Assert.IsTrue(tsr.Length > 0);
            // Validate the TSR
            TSA.ValidateResponse(tsq, tsr);
            // Validate the source
            TSA.ValidateSourceTsr(tsr, hash);
            // Extract the timestamp token
            byte[] token = TSA.ExtractToken(tsr);
            Assert.IsNotNull(token);
            Assert.IsTrue(token.Length > 0);
            // Validate the timestamp token
            TSA.ValidateSourceToken(token, hash);
            // Get information
            Assert.IsTrue((TSA.RequestInfo(tsq)?.Count() ?? 0) > 0);
            Assert.IsTrue((TSA.ResponseInfo(tsr)?.Count() ?? 0) > 0);
            Assert.IsTrue((TSA.TokenInfo(token)?.Count() ?? 0) > 0);
        }
    }
}