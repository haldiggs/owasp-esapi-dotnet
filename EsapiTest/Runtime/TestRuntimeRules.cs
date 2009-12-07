using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owasp.Esapi;
using Owasp.Esapi.Interfaces;
using Rhino.Mocks;
using Owasp.Esapi.Runtime;

namespace EsapiTest.Runtime
{
    /// <summary>
    /// Summary description for TestRuntimeRules
    /// </summary>
    [TestClass]
    public class TestRuntimeRules
    {
        private MockRepository _mocks;
        private EsapiRuntime _runtime;

        [TestInitialize]
        public void Initialize()
        {
            _mocks = new MockRepository();
            _runtime = new EsapiRuntime();
        }


        [TestMethod]
        public void TestGetRuntime()
        {
            Assert.IsNotNull(_runtime);
        }

        [TestMethod]
        public void TestFluentAddInvalidRuleParams()
        {
            Assert.IsNotNull(_runtime);

            try {
                _runtime.Rules.Register(null, _mocks.StrictMock<IRule>());
                Assert.Fail("Null rule name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Rules.Register(string.Empty, _mocks.StrictMock<IRule>());
                Assert.Fail("Empty rule name");
            }
            catch (ArgumentException) {
            }

            try {
                _runtime.Rules.Register(Guid.NewGuid().ToString(), null);
                Assert.Fail("Null rule");
            }
            catch (ArgumentNullException) {
            }
        }

        [TestMethod]
        public void TestRemoveRule()
        {
            Assert.IsNotNull(_runtime);

            ObjectRepositoryMock.AssertMockAddRemove<IRule>(_mocks, _runtime.Rules);
        }
    }
}
